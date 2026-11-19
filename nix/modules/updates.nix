# services.sensr.updates: pull a prebuilt sensr system from a release manifest,
# import it into the store and switch to it (docs/PLAN.md §2.4 item 3, §6).
#
# The box never evaluates nixpkgs. An upgrade is: download the closure the
# release published for this board, check its sha256, `nix-store --import`,
# point the system profile at the toplevel and run its
# `switch-to-configuration switch`. A full system closure replaces every
# package at once, atomically, and leaves the previous generation in the
# profile for rollback.
#
# Who does what:
#   sensr-update.service        root; handles a request the UI dropped in
#                               /run/sensr/updates/request.json.
#   sensr-update-timer.service  root; checks (and, in auto mode, installs)
#                               on the schedule below.
#   sensr-update.timer          starts the latter.
#   sensr-update.path           starts the former when request.json appears.
#
# The web UI is unprivileged (sensr-api, ProtectSystem=strict), so it never
# installs anything itself: it writes a request and reads the status the
# service leaves in /run/sensr/updates/. That keeps every privileged action
# in one place and needs no new agent IPC op.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.sensr;
  upd = cfg.updates;
  inherit (lib)
    mkOption
    types
    ;

  runtimeDir = "/run/sensr";
  updateRun = "${runtimeDir}/updates";
  updateState = "/var/lib/sensr/updates";
  requestFile = "${updateRun}/request.json";
  statusFile = "${updateRun}/status.json";

  updateScript = pkgs.writeShellApplication {
    name = "sensr-update";
    runtimeInputs = with pkgs; [
      coreutils
      curl
      jq
      nix
      systemd
      util-linux
      zstd
    ];
    text = ''
      set -euo pipefail

      manifest_url=${lib.escapeShellArg upd.manifestUrl}
      board=${lib.escapeShellArg cfg.build.image}
      run_dir=${lib.escapeShellArg updateRun}
      state_dir=${lib.escapeShellArg updateState}
      status_file=${lib.escapeShellArg statusFile}
      request_file=${lib.escapeShellArg requestFile}
      state_file="$state_dir/state.json"
      work=""
      remote_tag=""
      remote_version=""
      remote_system=""
      remote_sha=""
      remote_path=""
      remote_notes=""
      last_checked=""
      last_installed=""
      trap 'if [ -n "''${work:-}" ]; then rm -rf "$work"; fi' EXIT

      mkdir -p "$run_dir" "$state_dir"
      # The UI (sensr-api) writes request.json and reads status.json here, so
      # the directory must stay group-writable even if a restart recreated it
      # after systemd-tmpfiles ran.
      chmod 0775 "$run_dir"
      chgrp sensr-api "$run_dir" 2>/dev/null || true

      # One writer at a time: the timer and a UI request must not import into
      # the store at once.
      exec 9>"$state_dir/lock"
      flock 9

      state_auto() {
        if [ -r "$state_file" ]; then
          jq -r '.auto // false' "$state_file"
        else
          echo ${lib.escapeShellArg (if upd.auto then "true" else "false")}
        fi
      }

      set_auto() {
        jq -n --argjson a "$1" '{auto: $a}' > "$state_file.tmp"
        mv "$state_file.tmp" "$state_file"
      }

      current_version() {
        cat /run/current-system/nixos-version 2>/dev/null || echo unknown
      }

      # The release manifest names the exact toplevel its closure contains.
      # Comparing store paths is what decides "up to date": the nixos label
      # alone is the nixpkgs revision and date, so two sensr builds from the
      # same nixpkgs would otherwise look identical.
      current_system() {
        readlink -f /run/current-system 2>/dev/null || true
      }

      # The status the UI reads. Every field is always present so the page
      # renders before the first check has run.
      write_status() {
        local phase=$1 message=$2 available=$3
        jq -n \
          --arg phase "$phase" \
          --arg message "$message" \
          --argjson available "$available" \
          --argjson auto "$(state_auto)" \
          --arg current "$(current_version)" \
          --arg image "$board" \
          --arg manifest "$manifest_url" \
          --arg checked "$last_checked" \
          --arg installed "$last_installed" \
          --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
          '{
            phase: $phase,
            message: $message,
            auto: $auto,
            current: {version: $current, image: $image},
            available: $available,
            manifest_url: $manifest,
            last_check: (if $checked == "" then null else $checked end),
            last_install: (if $installed == "" then null else $installed end),
            updated_at: $at
          }' > "$status_file.tmp"
        mv "$status_file.tmp" "$status_file"
        chmod 0644 "$status_file"
      }

      # Asset names in the manifest may be absolute URLs or bare file names
      # next to the manifest (a GitHub release page).
      asset_url() {
        case "$1" in
          *://*) printf '%s\n' "$1" ;;
          *) printf '%s/%s\n' "''${manifest_url%/*}" "$1" ;;
        esac
      }

      # Fetches the manifest and picks this board's entry; sets remote_tag,
      # remote_version, remote_system (URL), remote_sha, remote_path, remote_notes.
      fetch_manifest() {
        local mf="$work/manifest.json"
        if ! curl -fsSL --retry 3 --connect-timeout 10 -o "$mf" "$manifest_url"; then
          return 1
        fi
        if ! jq -e --arg b "$board" '.images[$b]' "$mf" >/dev/null 2>&1; then
          echo "manifest has no image for '$board'" >&2
          return 2
        fi
        remote_tag=$(jq -r '.tag // ""' "$mf")
        remote_version=$(jq -r '.version // ""' "$mf")
        remote_system=$(asset_url "$(jq -r --arg b "$board" '.images[$b].system' "$mf")")
        remote_sha=$(jq -r --arg b "$board" '.images[$b].sha256 // ""' "$mf")
        remote_path=$(jq -r --arg b "$board" '.images[$b].store_path // ""' "$mf")
        remote_notes=$(jq -r '.notes // ""' "$mf")
      }

      available_json() {
        jq -n \
          --arg version "$remote_version" \
          --arg sha "$remote_sha" \
          --arg url "$remote_system" \
          --arg path "$remote_path" \
          --arg notes "$remote_notes" \
          '{version: $version, sha256: $sha, url: $url, store_path: $path, notes: $notes}'
      }

      check() {
        last_checked=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        write_status checking "Checking for updates" null
        work=$(mktemp -d)
        if ! fetch_manifest; then
          write_status error "Could not read the update manifest" null
          return 1
        fi
        local cur
        cur=$(current_version)
        if [ -n "$remote_path" ] && [ "$remote_path" = "$(current_system)" ]; then
          write_status up-to-date "This system is up to date ($cur)" null
          return 0
        fi
        if [ -z "$remote_path" ] && [ "$remote_version" = "$cur" ]; then
          write_status up-to-date "This system is up to date ($cur)" null
          return 0
        fi
        write_status update-available "Release ''${remote_tag:-$remote_version} is available" "$(available_json)"
      }

      install() {
        work=$(mktemp -d)
        last_checked=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        if ! fetch_manifest; then
          write_status error "Could not read the update manifest" null
          return 1
        fi
        local cur
        cur=$(current_version)
        if [ -n "$remote_path" ] && [ "$remote_path" = "$(current_system)" ]; then
          write_status up-to-date "This system is up to date ($cur)" null
          return 0
        fi
        if [ -z "$remote_sha" ]; then
          write_status error "The manifest has no sha256 for '$board'" "$(available_json)"
          return 1
        fi
        write_status downloading "Downloading ''${remote_tag:-$remote_version}" "$(available_json)"

        local archive="$work/closure.tar.zst"
        if ! curl -fL --retry 3 --connect-timeout 10 -o "$archive" "$remote_system"; then
          write_status error "Download failed" "$(available_json)"
          return 1
        fi
        # Accept "sha256:<hex>" as well as a bare hex digest.
        local want="''${remote_sha#sha256:}"
        local got
        got=$(sha256sum "$archive" | cut -d' ' -f1)
        if [ "$want" != "$got" ]; then
          write_status error "sha256 mismatch: expected $want, got $got" "$(available_json)"
          return 1
        fi

        write_status installing "Importing ''${remote_tag:-$remote_version}" "$(available_json)"
        local imported
        mapfile -t imported < <(zstd -dc "$archive" | nix-store --import)
        # The archive carries the whole runtime closure; the toplevel is the
        # one imported path with a switch-to-configuration entry point.
        local toplevel=""
        local p
        for p in "''${imported[@]}"; do
          if [ -x "$p/init" ] && [ -x "$p/bin/switch-to-configuration" ]; then
            toplevel=$p
          fi
        done
        if [ -z "$toplevel" ]; then
          write_status error "The archive did not contain a system toplevel" "$(available_json)"
          return 1
        fi
        if [ -n "$remote_path" ] && [ "$toplevel" != "$remote_path" ]; then
          write_status error "The archive contains $toplevel, not the manifest's $remote_path" "$(available_json)"
          return 1
        fi

        # Keep the imported generation even if the switch fails: the operator
        # can then switch or boot it by hand.
        if ! nix-env -p /nix/var/nix/profiles/system --set "$toplevel"; then
          write_status error "Could not set the system profile" "$(available_json)"
          return 1
        fi

        write_status installing "Switching to ''${remote_tag:-$remote_version}" "$(available_json)"
        # Run the switch in its own transient unit: the activation restarts
        # changed units, and sensr-update.service is one of them. In this
        # unit's cgroup that restart could kill the script before it records
        # the outcome; a separate unit runs to completion either way.
        if ! systemd-run --unit=sensr-update-switch --collect --wait \
             "$toplevel/bin/switch-to-configuration" switch; then
          write_status error "switch-to-configuration failed; the previous generation still boots" "$(available_json)"
          return 1
        fi

        last_installed=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        write_status "done" "Updated to ''${remote_tag:-$remote_version}" null
      }

      # Handle the UI request. The file is removed before the action so a
      # second click during a long download is still there afterwards; the
      # loop consumes it, up to a point.
      handle_request() {
        local n=0 req
        while [ -r "$request_file" ] && [ "$n" -lt 10 ]; do
          n=$((n + 1))
          req=$(cat "$request_file") || true
          rm -f "$request_file"
          case "$(printf '%s' "$req" | jq -r '.mode // "check"')" in
            check) check ;;
            install) install ;;
            auto-on) set_auto true; write_status idle "Automatic updates are on" null ;;
            auto-off) set_auto false; write_status idle "Automatic updates are off" null ;;
            *) write_status error "Unknown update request" null ;;
          esac
        done
      }

      case "''${1:---timer}" in
        --check) check ;;
        --install) install ;;
        --handle) handle_request ;;
        --timer)
          # A request that arrived while the path unit was busy is still on
          # disk; handle it before the schedule runs.
          handle_request
          # Auto mode installs; otherwise the check still refreshes what the
          # page shows, so the operator sees a pending update.
          if [ "$(state_auto)" = true ]; then
            install
          else
            check
          fi
          ;;
        *) echo "usage: sensr-update [--check|--install|--handle|--timer]" >&2; exit 2 ;;
      esac
    '';
  };
in
{
  options.services.sensr.updates = {
    enable = mkOption {
      type = types.bool;
      default = true;
      description = "Enable in-app system updates (the System > Updates page).";
    };
    manifestUrl = mkOption {
      type = types.str;
      default = "https://github.com/itpick/sensr/releases/latest/download/update-manifest.json";
      description = ''
        The release manifest that lists, per image, the system closure and its
        sha256 (see `.github/workflows/release.yml`). Relative asset names are
        resolved against this URL's directory.
      '';
    };
    auto = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Install a newer system automatically on the timer. Off by default: a
        switch restarts the sensr services for a few seconds, so the operator
        decides when that happens until they turn it on in System > Updates.
      '';
    };
    interval = mkOption {
      type = types.str;
      default = "6h";
      description = "How often the timer checks (systemd time span).";
    };
  };

  config = lib.mkIf (cfg.enable && upd.enable) {
    # The UI writes request.json (group sensr-api) and reads status.json
    # (0644); only root may touch the state directory.
    systemd.tmpfiles.rules = [
      "d ${updateRun} 0775 root sensr-api -"
      "d ${updateState} 0700 root root -"
    ];

    systemd.services.sensr-update = {
      description = "sensr system update: handle a web UI request";
      # switch-to-configuration installs a new ExecStart for this unit. Do not
      # restart it there: the script that started the switch must keep running
      # so it can record the outcome in status.json.
      restartIfChanged = false;
      wants = [ "network-online.target" ];
      after = [
        "network-online.target"
        "nix-daemon.service"
      ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${updateScript}/bin/sensr-update --handle";
        # A download on a slow link may take a while; the switch itself is
        # quick, and a wedged transfer must not hold the lock forever.
        TimeoutStartSec = "1h";
        Nice = 10;
        IOSchedulingClass = "best-effort";
        # Root, but only the paths an import and a switch need.
        # switch-to-configuration updates /etc, the systemd state under
        # /var and the bootloader on /boot; everything else stays read-only.
        ProtectSystem = "strict";
        ReadWritePaths = [
          "/nix"
          "/run"
          "/etc"
          "/var"
          "/boot"
          updateState
        ];
        PrivateTmp = true;
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelLogs = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
        SystemCallFilter = [
          "@system-service"
          "@mount"
        ];
      };
    };

    systemd.services.sensr-update-timer = {
      description = "sensr system update: scheduled check";
      # See sensr-update.service: the script outlives the switch it starts.
      restartIfChanged = false;
      wants = [ "network-online.target" ];
      after = [
        "network-online.target"
        "nix-daemon.service"
      ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${updateScript}/bin/sensr-update --timer";
        TimeoutStartSec = "1h";
        Nice = 10;
        IOSchedulingClass = "best-effort";
        ProtectSystem = "strict";
        ReadWritePaths = [
          "/nix"
          "/run"
          "/etc"
          "/var"
          "/boot"
          updateState
        ];
        PrivateTmp = true;
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelLogs = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
        SystemCallFilter = [
          "@system-service"
          "@mount"
        ];
      };
    };

    # A UI request starts the handler.
    systemd.paths.sensr-update = {
      description = "Watch for an update request from the web UI";
      wantedBy = [ "multi-user.target" ];
      pathConfig.PathExists = requestFile;
      pathConfig.Unit = "sensr-update.service";
    };

    systemd.timers.sensr-update = {
      description = "Check for sensr updates";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "5min";
        OnUnitInactiveSec = upd.interval;
        RandomizedDelaySec = "10min";
        Unit = "sensr-update-timer.service";
      };
    };
  };
}