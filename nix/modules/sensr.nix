# services.sensr: the sensr appliance on NixOS (docs/PLAN.md §2.3, §2.4, §6).
#
# The closure is immutable: it carries the sensr binaries, every daemon the
# appliers drive and a unit for each. What those daemons do comes from the
# typed runtime config that sensr-agent renders into /run/sensr at apply time
# (§2.4 "hybrid apply"), never from Nix options here.
#
# Contract with the Rust crates (also in nix/README.md):
#
#   sensr-agent   root, capabilities bounded, owns /var/lib/sensr (0700).
#                 Serves IPC on $SENSR_AGENT_SOCKET (/run/sensr/agent.sock); makes
#                 it 0660 root:sensr. Renders daemon configs to
#                 /run/sensr/<daemon>/ and networkd files to
#                 /run/systemd/network/, then starts or reloads the units
#                 below over D-Bus. Reads seeds once from $SENSR_SEED_DIR.
#   sensr-api     static user sensr-api (in group sensr): reaches the agent
#                 only through the socket and cannot read /var/lib/sensr. The
#                 agent trusts its uid to act for the principals it
#                 authenticated (SO_PEERCRED carries only the primary ids,
#                 so this cannot be a DynamicUser).
#   sensr (CLI)   members of group sensr (and root) talk to the same socket.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.sensr;
  inherit (lib)
    mkOption
    mkEnableOption
    mkIf
    mkDefault
    types
    ;

  runtimeDir = "/run/sensr";
  stateDir = "/var/lib/sensr";
  socket = "${runtimeDir}/agent.sock";

  # Fixed ids: the agent is told them on its command line (socket group,
  # trusted API uid), and they must be the same on every boot.
  sensrGid = 730;
  apiUid = 731;

  # The daemons sensr-agent drives. They are in the agent's PATH and in
  # systemPackages (operators use nft/wg/unbound-control for diagnosis).
  kea = pkgs.sensr-kea;
  suricata = pkgs.suricata;
  # suricata-update is Python and needs PyYAML at run time
  suricataPython = pkgs.python3.withPackages (ps: [ ps.pyyaml ]);
  # Suricata's command lines are rendered by the agent (capture mode, queue
  # numbers), one argument per line, so nothing is re-split by a shell.
  suricataStart = pkgs.writeShellScript "sensr-suricata-start" ''
    set -eu
    mapfile -t args < ${runtimeDir}/suricata/suricata.args
    exec ${suricata}/bin/suricata "''${args[@]}"
  '';
  suricataUpdate = pkgs.writeShellScript "sensr-suricata-update" ''
    set -eu
    mapfile -t args < ${runtimeDir}/suricata/update.args
    exec ${suricataPython.interpreter} ${suricata}/bin/suricata-update update "''${args[@]}"
  '';
  suricataSeed = pkgs.writeShellScript "sensr-suricata-seed" ''
    set -eu
    mkdir -p /var/lib/suricata/rules /var/lib/suricata/cache
    # the classification and reference tables until the first rule update
    # brings the sources' own
    for f in classification.config reference.config; do
      # the engine and the updater may both get here first
      if [ ! -e /var/lib/suricata/rules/$f ]; then
        # cp keeps the store file's 0444 mode, and suricata-update rewrites
        # these files in place, so give the owner write access back
        cp ${suricata}/etc/suricata/$f /var/lib/suricata/rules/$f && \
          chmod 0644 /var/lib/suricata/rules/$f || true
      fi
    done
  '';
  # Unbound with dnstap: the resolver streams client queries/responses to
  # sensr-insight (per-host DNS activity). withDNSTAP pulls in protobuf-c.
  unboundPkg = pkgs.unbound.override { withDNSTAP = true; };
  appliedPackages = with pkgs; [
    nftables
    kea
    unboundPkg
    cfg.ntp.package
    wireguard-tools
    iproute2
    conntrack-tools
    ethtool
    suricata
  ];

  # /etc/sensr/version.json: the manifest of what this generation is
  # (06 §1 L1/L11) and the input of the selftest rows T-0391, T-0393 and
  # T-0397.
  versionJson = {
    product_id = "sensr";
    product_name = "sensr";
    version = cfg.package.version;
    git_rev = cfg.build.gitRev;
    nixpkgs_rev = config.system.nixos.revision or "unknown";
    nixos_release = config.system.nixos.release;
    system = pkgs.stdenv.hostPlatform.system;
    kernel = config.boot.kernelPackages.kernel.modDirVersion;
    package = "${cfg.package}";
    agent = "${cfg.package}/bin/sensr-agent";
    api = "${cfg.package}/bin/sensr-api";
    cli = "${cfg.package}/bin/sensr";
    image = cfg.build.image;
    daemons = lib.listToAttrs (
      map (p: lib.nameValuePair (lib.getName p) (lib.getVersion p)) appliedPackages
    );
  };

  pending = cfg.pending;

  selftest = pkgs.writeShellApplication {
    name = "sensr-selftest";
    runtimeInputs = with pkgs; [
      coreutils
      gnugrep
      jq
      nix
      config.systemd.package
      cfg.package
    ];
    # Each row is one boot selftest check from docs/research/03 §2.7
    # (OPNsense's rc.syshook.d/early/99-selftest). The Rust selftest in
    # sensr-agent replaces this script once it exists; the row IDs stay.
    text = ''
      out=/run/sensr-selftest/result.json
      v=/etc/sensr/version.json
      rows='[]'
      failed=0
      row() { # id status detail
        rows=$(jq -c --arg id "$1" --arg s "$2" --arg d "$3" '. + [{id: $id, status: $s, detail: $d}]' <<<"$rows")
        echo "sensr-selftest: $1 $2 $3"
        if [ "$2" = fail ]; then failed=1; fi
      }

      # T-0391: the product is determinable.
      if jq -e '.product_id == "sensr"' "$v" >/dev/null 2>&1; then
        row T-0391 pass "version.json product_id is sensr"
      else
        row T-0391 fail "$v missing, unparsable or product_id is not sensr"
      fi

      # T-0392: the current generation resolves.
      if sys=$(readlink -e /run/current-system); then
        row T-0392 pass "$sys"
      else
        row T-0392 fail "/run/current-system does not resolve"
      fi

      # T-0393: the agent recorded in version.json is in this closure.
      pkgpath=$(jq -r .package "$v" 2>/dev/null || true)
      agent=$(jq -r .agent "$v" 2>/dev/null || true)
      if [ -x "$agent" ] && nix-store -qR /run/current-system | grep -qxF "$pkgpath"; then
        row T-0393 pass "$agent"
      else
        row T-0393 fail "agent $agent not in the system closure"
      fi

      # T-0397: the running kernel is the one this generation was built with.
      want=$(jq -r .kernel "$v" 2>/dev/null || true)
      if [ "$(uname -r)" = "$want" ]; then
        row T-0397 pass "$want"
      else
        row T-0397 fail "running $(uname -r), version.json says $want"
      fi

      # T-0401: the config store answers over IPC.
      ${
        if pending.configGet then
          ''row T-0401 pending "sensr config get waits on sensr-ipc/sensr-config (nix/pending.nix)"''
        else
          ''
            # After a switch the agent restarts alongside this unit and may
            # not be listening yet: give it up to 30 s before failing.
            ok=0
            for _ in $(seq 1 30); do
              if sensr config get --json 2>/dev/null | jq -e 'type == "object"' >/dev/null; then
                ok=1
                break
              fi
              sleep 1
            done
            if [ "$ok" = 1 ]; then
              row T-0401 pass "sensr config get returned an object"
            else
              row T-0401 fail "sensr config get --json did not return an object"
            fi
          ''
      }

      mkdir -p "$(dirname "$out")"
      jq -n --argjson rows "$rows" --argjson failed "$failed" \
        '{result: (if $failed == 1 then "fail" else "pass" end), rows: $rows}' >"$out.tmp"
      mv "$out.tmp" "$out"
      if [ "$failed" = 1 ]; then
        echo "sensr-selftest: FAIL"
        exit 1
      fi
      echo "sensr-selftest: PASS"
    '';
  };

  trialHealth = pkgs.writeShellApplication {
    name = "sensr-trial-health";
    runtimeInputs = with pkgs; [
      coreutils
      gnugrep
      gnused
      iproute2
      dig
      curl
      inetutils
      # blkid and mount, for the trial's own boot partition (revert)
      util-linux
      config.systemd.package
    ];
    # Checks fail softly and are reported; the script decides when to reboot.
    bashOptions = [ ];
    text = builtins.replaceStrings [ "@seedDir@" ] [ cfg.seedDir ] (
      builtins.readFile ../pi5/trial-health.sh
    );
  };

  seedReadme = pkgs.writeText "sensr-seed-README.txt" (
    builtins.replaceStrings [ "@SEED_DIR@" ] [ cfg.seedDir ] (builtins.readFile ./seed-README.txt)
  );

  # Hardening shared by the units sensr runs (systemd.exec(5)). The agent
  # loosens only what applying network config needs.
  commonHardening = {
    NoNewPrivileges = true;
    ProtectHome = true;
    PrivateTmp = true;
    ProtectKernelModules = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    RestrictNamespaces = true;
    SystemCallArchitectures = "native";
    UMask = "0077";
  };
in
{
  options.services.sensr = {
    enable = mkEnableOption "sensr, the Rust firewall/router appliance";

    package = mkOption {
      type = types.package;
      default = pkgs.sensr;
      defaultText = lib.literalExpression "pkgs.sensr";
      description = "The sensr workspace build (sensr-agent, sensr-api, sensr).";
    };

    configFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Declarative mode (docs/PLAN.md §2.4 item 6): a sensr config document
        that the agent applies at boot as the source of truth. The UI is then
        read-only and a change is a nixos-rebuild.
      '';
    };

    applier = mkOption {
      type = types.enum [
        "preview"
        "slice"
      ];
      default = "preview";
      description = ''
        What the agent does on apply ($SENSR_APPLIER): `preview` only plans
        (nothing on the box changes); `slice` drives the sensr-apply
        appliers (networkd, nftables, sysctl, Kea, Unbound, WireGuard).
      '';
    };

    ssh.enable = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Run sshd, key-only. Keys come from /run/sensr/ssh/authorized_keys/<user>
        (rendered by the agent from the config's users) and, until the agent
        imports it, from the seed folder's authorized_keys (for root). The
        WAN never reaches it: sensr's rules drop WAN traffic to the box
        unless a rule passes it.
      '';
    };

    seedDir = mkOption {
      type = types.str;
      default = "/boot/sensr";
      description = ''
        The first-boot seed folder on the image's FAT partition
        (docs/PLAN.md §6): /boot/sensr on x86, /boot/firmware/sensr on the Pi.
      '';
    };

    api = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Run sensr-api, the HTTP API and web UI.";
      };
      listen = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Override for development and tests ($SENSR_API_LISTEN): serve on
          this one address. By default sensr-api listens where the config's
          `system.webgui` says (port, interfaces, HTTP redirect), over HTTPS
          with the certificate the agent hands it.
        '';
      };
      insecureHttp = mkOption {
        type = types.bool;
        default = false;
        description = "With `listen`: plain HTTP instead of HTTPS (credentials in clear).";
      };
      uiRoot = mkOption {
        type = types.nullOr types.path;
        default = "${cfg.package}/share/sensr/ui";
        defaultText = lib.literalExpression ''"''${cfg.package}/share/sensr/ui"'';
        description = ''
          Document root of the web UI (`cargo leptos build` output: `pkg/`,
          `favicon.svg`). The server-rendered pages work without it; the
          assets that make them interactive are served from here. `null`
          serves the API alone.
        '';
      };
    };

    initrdTimeoutSec = mkOption {
      type = types.ints.positive;
      default = 300;
      description = ''
        Force a reboot when stage 1 has not reached
        initrd.target this many seconds after boot (a hung root mount, a hung
        unit). On a Pi trial boot the reboot returns to the previous OS.
      '';
    };

    ntp.package = lib.mkPackageOption pkgs "ntpd-rs" { } // {
      description = ''
        The NTP daemon sensr renders `ntp.toml` for (ntpd-rs: memory safe,
        NTS-capable). It keeps the clock from `system.time_servers` and serves
        clients per the `ntp` section, so systemd-timesyncd is off, as
        OPNsense runs ntpd whenever time servers are set.
      '';
    };

    selftest.enable = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Run the boot selftest (T-0391..T-0401) before boot-complete.target, so
        a generation that fails it is never blessed by boot counting.
      '';
    };

    pending = mkOption {
      type = types.attrsOf types.bool;
      default = import ../pending.nix;
      defaultText = lib.literalExpression "import ./nix/pending.nix";
      description = "Parts of sensr that have not landed yet (see nix/pending.nix).";
    };

    build = {
      gitRev = mkOption {
        type = types.str;
        default = "unknown";
        description = "The sensr git revision this system was built from (set by flake.nix).";
      };
      image = mkOption {
        type = types.str;
        default = "none";
        description = "The image variant (qcow, pi5, ...) for version.json.";
      };
    };
  };

  imports = [ ./updates.nix ];

  config = mkIf cfg.enable {
    # sensr owns the packet filter and the interfaces. NixOS's own firewall
    # and its nftables service would flush the ruleset sensr applies.
    networking.firewall.enable = false;
    networking.nftables.enable = false;
    # WAN DHCPv4 goes through networkd in Phase 1 (PLAN §2.1); the agent
    # renders .network/.netdev files into /run/systemd/network.
    networking.useNetworkd = true;
    networking.useDHCP = false;
    systemd.network.enable = true;
    # Unbound (rendered by the agent) is the resolver and listens on :53 on
    # every interface; resolved's stub listener would hold the port.
    services.resolved.settings.Resolve.DNSStubListener = "no";
    # Routing is the product; the agent still owns per-interface sysctls.
    boot.kernel.sysctl = {
      "net.ipv4.ip_forward" = mkDefault 1;
      "net.ipv6.conf.all.forwarding" = mkDefault 1;
    };
    # Loaded up front: the agent runs with ProtectKernelModules.
    boot.kernelModules = [
      "nf_tables"
      "nft_ct"
      "nft_nat"
      "nft_masq"
      "nft_reject_inet"
      "nf_conntrack"
      "wireguard"
      "8021q"
      # IDS: af-packet capture, NFQUEUE for prevent mode
      "af_packet"
      "nft_queue"
      "nfnetlink_queue"
    ];

    users.groups.sensr.gid = sensrGid;
    users.groups.suricata = { };
    # Unbound (DynamicUser sensr-unbound) connects to the dnstap socket that
    # sensr-insight creates. Both units list this group as a supplementary
    # group (a dynamic user has no /etc/group membership to rely on).
    users.groups.sensr-dnstap = { };
    users.users.sensr-insight = {
      isSystemUser = true;
      group = "sensr";
      extraGroups = [
        "suricata"
        "sensr-dnstap"
      ];
      description = "sensr traffic insight";
    };
    users.users.suricata = {
      isSystemUser = true;
      group = "suricata";
      description = "Suricata IDS";
    };
    users.groups.sensr-api.gid = apiUid;
    users.users.sensr-api = {
      isSystemUser = true;
      uid = apiUid;
      group = "sensr-api";
      extraGroups = [ "sensr" ];
      description = "sensr API";
    };

    environment.systemPackages = [
      cfg.package
      trialHealth
      # the guard's built-in packs and pack keys, at the paths sensr-guard
      # and the API know (/run/current-system/sw/share/sensr-guard/...)
      pkgs.sensr-guard-bpf
      pkgs.sensr-guard-keys
    ]
    ++ appliedPackages;

    # The runtime guard's programs are BPF LSM programs: the bpf LSM must be
    # in lsm= (NixOS puts it last by default) and lockdown must not be
    # confidentiality, which keeps them from reading kernel memory
    # (sensr-guard refuses to start then).
    assertions = [
      {
        assertion = lib.elem "bpf" config.security.lsm;
        message = "services.sensr: security.lsm must include \"bpf\" (sensr-guard's programs are BPF LSM programs)";
      }
      {
        # one lsm= only (the one security.lsm renders): a second would
        # override it on the command line
        assertion =
          lib.filter (lib.hasPrefix "lsm=") config.boot.kernelParams == [
            "lsm=${lib.concatStringsSep "," config.security.lsm}"
          ];
        message = "services.sensr: set the LSMs with security.lsm, not an lsm= kernel parameter";
      }
      {
        assertion = !(lib.elem "lockdown=confidentiality" config.boot.kernelParams);
        message = "services.sensr: lockdown=confidentiality stops sensr-guard's BPF programs";
      }
    ];
    environment.etc."sensr/version.json".text = builtins.toJSON versionJson;

    environment.variables.SENSR_AGENT_SOCKET = socket;

    # networkd reads runtime config from here; the agent writes into it.
    systemd.tmpfiles.rules = [
      "d /run/systemd/network 0755 root root -"
      # unbound.conf globs for sensr-dns's include files here; Unbound
      # accepts a glob that matches nothing, not one in a missing directory.
      "d /var/lib/sensr-dns 0755 root root -"
    ];

    # MAC pins (docs/PLAN.md §6 L3): the agent renders one systemd.link file
    # per card bound by MAC and keeps a copy in the state directory, because
    # /run is empty at boot. This puts them back before udev names the cards,
    # so a card that moved to another slot or USB port keeps its name, and
    # with it its network.
    #
    # This unit runs before udev's coldplug, so it must not wait for anything
    # coldplug makes. The seed folder is one: on a Pi it is on the FAT
    # partition, mounted from /dev/disk/by-label/FIRMWARE, and that link only
    # exists once coldplug has run. Waiting for the seed here (as
    # WantsMountsFor did until 2026-11-24) was a dependency cycle that only
    # the mount's 90 s device timeout broke: every Pi 5 boot sat silent from
    # ~13 s to ~98 s, long enough to look hung and be power-cycled. The seed's
    # first-boot names are sensr-ifnames-seed's job, after coldplug.
    systemd.services.sensr-ifnames = {
      description = "Restore sensr's MAC-pinned NIC names before udev names cards";
      wantedBy = [ "sysinit.target" ];
      before = [
        "systemd-udev-trigger.service"
        "systemd-networkd.service"
      ];
      unitConfig = {
        DefaultDependencies = false;
        # the root filesystem: mounted by the initrd, before any of this
        RequiresMountsFor = stateDir;
      };
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = pkgs.writeShellScript "sensr-ifnames" ''
          set -eu
          mkdir -p /run/systemd/network
          for f in ${stateDir}/links/10-sensr-*.link; do
            [ -e "$f" ] || continue
            cp "$f" /run/systemd/network/
          done
        '';
      };
    };

    # First boot: no links in the state directory yet, and the agent imports
    # the seed later (multi-user), so without this the cards keep their kernel
    # names for a whole boot and the network comes up on the wrong names --
    # which the trial gate reads as a failure and reboots. The seed's ifnames
    # says which MAC is which device; render the same .link files the agent
    # would, then replay the cards' udev events so they are renamed before
    # networkd configures them. Every later boot exits at once.
    systemd.services.sensr-ifnames-seed = {
      description = "Name NICs from the seed folder's ifnames on a first boot";
      wantedBy = [ "sysinit.target" ];
      after = [
        "sensr-ifnames.service"
        "systemd-udev-trigger.service"
      ];
      before = [ "systemd-networkd.service" ];
      unitConfig.DefaultDependencies = false;
      path = [
        pkgs.coreutils
        config.systemd.package
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = pkgs.writeShellScript "sensr-ifnames-seed" ''
          set -eu
          for f in /run/systemd/network/10-sensr-*.link; do
            if [ -e "$f" ]; then
              echo "names restored from ${stateDir}/links; the seed's ifnames is not needed"
              exit 0
            fi
          done
          seed=${lib.escapeShellArg cfg.seedDir}
          # When the seed is on a file system of its own (the Pi's FAT, nofail),
          # start its mount and wait for it, but not for long: a missing seed
          # is a boot on kernel names, not a boot without a network. Not an
          # ordering dependency, which would hold networkd on every boot.
          mp=$(dirname "$seed")
          unit=$(systemd-escape -p --suffix=mount "$mp")
          if [ "$(systemctl show -P LoadState "$unit")" = loaded ]; then
            timeout 30 systemctl start "$unit" \
              || echo "$unit is not up after 30 s; no names from the seed" >&2
          fi
          [ -r "$seed/ifnames" ] || exit 0
          mkdir -p /run/systemd/network
          n=0
          while read -r mac name _; do
            [ -n "''${mac:-}" ] || continue
            case $mac in \#*) continue ;; esac
            [ -n "''${name:-}" ] || continue
            {
              echo "# Generated by sensr from the seed's ifnames (first boot)."
              echo "[Match]"
              echo "PermanentMACAddress=''${mac,,}"
              echo "[Link]"
              echo "Name=$name"
              echo "AlternativeNamesPolicy=database onboard slot path mac"
              echo "MACAddressPolicy=persistent"
            } > "/run/systemd/network/10-sensr-$name.link"
            n=$((n + 1))
          done < "$seed/ifnames"
          [ "$n" -gt 0 ] || exit 0
          echo "naming $n card(s) from $seed/ifnames"
          # coldplug already named the cards; replay their add events with
          # the new .link files (nothing has brought them up yet)
          udevadm control --reload
          udevadm trigger --action=add --subsystem-match=net
          udevadm settle --timeout=30 || true
        '';
      };
    };

    # Ethernet adapter watchdog: USB adapters that wedge after an xHCI reset,
    # and the Pi 5's built-in port (macb) when its transmit queue stalls.
    # The script and its reasons: nix/modules/nic-recover.sh (tests:
    # nix/modules/nic-recover-test.sh).
    #
    # One tick every 5 s, from a long-running loop rather than a timer. On
    # 2026-11-25 the WAN (macb) stalled for 36 s and the 30 s timer bounced
    # it only after 40 s; at 5 s a lasting stall (two rising ticks) is cured
    # in about 10-15 s. A 5 s timer would log "Starting/Finished" twice every
    # 5 s to the SD card; the loop logs only what the script says.
    systemd.services.sensr-nic-recover =
      let
        tick = pkgs.writeShellScript "sensr-nic-recover" (
          builtins.replaceStrings
            [ "@ethtool@" "@ip@" "@systemctl@" ]
            [
              "${pkgs.ethtool}/bin/ethtool"
              "${pkgs.iproute2}/bin/ip"
              "${config.systemd.package}/bin/systemctl"
            ]
            (builtins.readFile ./nic-recover.sh)
        );
      in
      {
        description = "Prevent and recover Ethernet adapter wedges (USB adapters, Pi 5 macb)";
        wantedBy = [ "multi-user.target" ];
        # Everything the script calls besides the three store paths above. A
        # missing tool fails quietly: `awk` was not here, and the macb RX ring
        # was never raised (2026-11-23).
        path = [
          pkgs.coreutils
          pkgs.findutils
          pkgs.gnugrep
          pkgs.gnused
          pkgs.gawk
        ];
        serviceConfig = {
          Type = "simple";
          # The first tick waits as the timer's OnBootSec did, so a booting
          # system's adapters settle first; a restart of the unit later on
          # starts ticking right away.
          ExecStart = pkgs.writeShellScript "sensr-nic-recover-loop" ''
            up=$(cut -d. -f1 /proc/uptime)
            [ "$up" -lt 90 ] && sleep $((90 - up))
            while :; do
              ${tick}
              sleep 5
            done
          '';
          Restart = "always";
          RestartSec = 5;
        };
      };

    systemd.targets.sensr-net = {
      description = "sensr has applied interfaces, addresses and routes";
      after = [ "sensr-agent.service" ];
    };

    systemd.services.sensr-agent = {
      description = "sensr agent: config store and apply engine";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-pre.target" ];
      after = [
        "network-pre.target"
        "local-fs.target"
        "systemd-networkd.service"
      ];
      before = [
        "network.target"
        "sensr-net.target"
      ];
      # The seed is on the image's FAT partition, which the Pi image mounts
      # with `nofail`: local-fs.target does not wait for it, so ordering on
      # local-fs.target alone let the agent read the seed folder before the
      # mount was up, get ENOENT, log `NoSeed` and never retry — every trial
      # boot came up on factory defaults instead of the seeded config.
      # WantsMountsFor adds the mount to this transaction and orders after it
      # without making the agent's start depend on it: a missing seed is a
      # factory-default boot, not a reason for no router. (RequiresMountsFor,
      # as the boot-log writers use, would fail the agent with the mount.)
      unitConfig.WantsMountsFor = cfg.seedDir;
      path = appliedPackages ++ [ config.systemd.package ];
      environment = {
        SENSR_AGENT_SOCKET = socket;
        SENSR_RUNTIME_DIR = runtimeDir;
        SENSR_STATE_DIR = stateDir;
        SENSR_SEED_DIR = cfg.seedDir;
        SENSR_NETWORKD_DIR = "/run/systemd/network";
        SENSR_APPLIER = cfg.applier;
        RUST_LOG = "info";
      }
      // lib.optionalAttrs (cfg.configFile != null) { SENSR_CONFIG_FILE = "${cfg.configFile}"; };
      serviceConfig = commonHardening // {
        # READY=1 once the socket is bound and the boot apply has run; the
        # agent also pets the watchdog.
        Type = "notify";
        NotifyAccess = "main";
        WatchdogSec = "30s";
        # WantsMountsFor above is only an ordering hint while the mount is
        # still in the transaction. When the FAT's by-label device is late
        # (udev can hold it behind the WiFi SDIO deferred probe), the mount
        # unit fails first and the agent then starts before it without any
        # ordering at all: it reads an empty /boot/firmware, logs NoSeed and
        # the seeded config is silently ignored. Wait for the mount here
        # instead (bootlog.sh starts it the same way). Nothing happens when
        # the seed is not on its own mount, so x86 is unaffected.
        ExecStartPre = pkgs.writeShellScript "sensr-agent-wait-seed" ''
          set -u
          seed=${lib.escapeShellArg cfg.seedDir}
          mp=$(${pkgs.coreutils}/bin/dirname "$seed")
          # This wait is on the boot path, so report what it cost: the boot
          # time work needs the number, not a guess.
          t0=$(${pkgs.coreutils}/bin/date +%s%N)
          trap 'echo "sensr-agent-wait-seed: waited $(( ($(${pkgs.coreutils}/bin/date +%s%N) - t0) / 1000000 )) ms" >&2' EXIT
          # Not `mountpoint`: ProtectSystem=strict below gives this service its
          # own mount namespace with /boot/firmware bind-mounted from the
          # ReadWritePaths entry, so mountpoint reports it as a mount point
          # even when the FAT is not mounted and the path is an empty
          # directory on the root filesystem. That is exactly how the seed
          # came to be read too early. The FAT's filesystem type is the
          # honest test, and the host mount propagates into the namespace.
          fatfs=$(${pkgs.util-linux}/bin/findmnt -n -o FSTYPE --mountpoint "$mp" 2>/dev/null || true)
          if [ "$fatfs" = vfat ]; then exit 0; fi
          unit=$(${config.systemd.package}/bin/systemd-escape -p --suffix=mount "$mp") || exit 0
          # Do not ask systemctl whether the unit exists: `systemctl cat` goes
          # through D-Bus, and at this point in the boot dbus-broker is still
          # starting (the agent is ordered before network.target, so it runs
          # at ~26 s, dbus at ~27 s). That made the check fail, the script
          # exit early, and the agent read the seed folder before the mount
          # just as before. The unit files are on disk; look there instead.
          found=0
          for d in /run/systemd/generator.early /run/systemd/generator /run/systemd/system /etc/systemd/system; do
            if [ -e "$d/$unit" ]; then found=1; break; fi
          done
          [ "$found" = 1 ] || exit 0
          ${config.systemd.package}/bin/systemctl start --no-block "$unit" 2>/dev/null || true
          # Bounded: the mount's own device timeout decides how long systemd
          # waits, and the agent must still start on factory defaults if the
          # partition is genuinely not there.
          for _ in $(${pkgs.coreutils}/bin/seq 1 40); do
            fatfs=$(${pkgs.util-linux}/bin/findmnt -n -o FSTYPE --mountpoint "$mp" 2>/dev/null || true)
            if [ "$fatfs" = vfat ]; then exit 0; fi
            ${pkgs.coreutils}/bin/sleep 0.25
          done
          exit 0
        '';
        ExecStart = lib.escapeShellArgs (
          [
            "${cfg.package}/bin/sensr-agent"
            "--socket"
            socket
            "--socket-mode"
            "660"
            "--socket-gid"
            (toString sensrGid)
            "--state-dir"
            stateDir
            "--trust-uid"
            (toString apiUid)
          ]
          ++ lib.optionals (cfg.configFile != null) [
            "--seed"
            "${cfg.configFile}"
          ]
        );
        Restart = "on-failure";
        RestartSec = 2;
        # /run/sensr holds the socket and the rendered daemon configs; it
        # must outlive an agent restart, or the daemons lose their files.
        RuntimeDirectory = "sensr";
        RuntimeDirectoryMode = "0755";
        RuntimeDirectoryPreserve = "yes";
        StateDirectory = "sensr";
        StateDirectoryMode = "0700";
        # Root, but only with the capabilities applying config needs:
        # netlink/nft/wg (NET_ADMIN), raw sockets for probes (NET_RAW),
        # binding helpers (NET_BIND_SERVICE), remounting the seed partition
        # (SYS_ADMIN), handing rendered files to daemon users (CHOWN, FOWNER),
        # signalling them (KILL), and reading Kea's lease files, which the
        # DynamicUser daemon writes 0640 as nobody:nogroup (DAC_READ_SEARCH;
        # without it the host inventory never sees a lease).
        CapabilityBoundingSet = [
          "CAP_DAC_READ_SEARCH"
          "CAP_NET_ADMIN"
          "CAP_NET_RAW"
          "CAP_NET_BIND_SERVICE"
          "CAP_SYS_ADMIN"
          "CAP_CHOWN"
          "CAP_FOWNER"
          "CAP_KILL"
        ];
        ProtectSystem = "strict";
        ReadWritePaths = [
          runtimeDir
          # created by tmpfiles below; "-": a missing path must not stop the agent
          "-/run/systemd/network"
          # runtime drop-ins (the IDS update timer's schedule)
          "-/run/systemd/system"
          "-${cfg.seedDir}"
          "-/boot/firmware"
        ];
        # Per-interface sysctls (forwarding, rp_filter, accept_ra).
        ProtectKernelTunables = false;
        ProtectKernelLogs = true;
        ProtectHostname = false;
        # system.timezone: `timedatectl set-timezone` asks systemd-timedated over
        # the system bus (AF_UNIX; `time.timeZone` stays unset so the zone is
        # mutable). The agent never writes /etc/localtime itself.
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_NETLINK"
          "AF_INET"
          "AF_INET6"
          "AF_PACKET"
        ];
        SystemCallFilter = [
          "@system-service"
          "@mount"
        ];
      };
    };

    systemd.services.sensr-api = mkIf cfg.api.enable {
      description = "sensr API and web UI";
      wantedBy = [ "multi-user.target" ];
      # Not ordered after the agent: the API connects to the agent socket
      # per request, so the management UI answers while the agent is still
      # running its boot apply (and reports the agent as unavailable for
      # the second or so before its socket exists).
      wants = [ "sensr-agent.service" ];
      environment = {
        SENSR_AGENT_SOCKET = socket;
        RUST_LOG = "info";
      };
      serviceConfig = commonHardening // {
        Type = "exec";
        ExecStart = lib.escapeShellArgs (
          [ "${cfg.package}/bin/sensr-api" ]
          ++ lib.optionals (cfg.api.listen != null) [
            "--listen"
            cfg.api.listen
          ]
          ++ lib.optional (cfg.api.uiRoot != null) "--ui-root"
          ++ lib.optional (cfg.api.uiRoot != null) (toString cfg.api.uiRoot)
          ++ lib.optional cfg.api.insecureHttp "--insecure-http"
        );
        Restart = "on-failure";
        RestartSec = 2;
        User = "sensr-api";
        Group = "sensr-api";
        SupplementaryGroups = [ "sensr" ];
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
        ProtectSystem = "strict";
        # The API process never sees the store or its secrets (PLAN §2.1).
        InaccessiblePaths = [ stateDir ];
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelLogs = true;
        ProtectHostname = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
          "~@resources"
        ];
      };
    };

    # Daemons the agent renders and drives. Each waits for its config file,
    # so a box whose config does not enable it never starts it. The agent
    # starts or reloads them after writing the file (SIGHUP reloads both).
    systemd.services.sensr-kea-dhcp4 = {
      description = "Kea DHCPv4 server (config rendered by sensr)";
      after = [ "sensr-net.target" ];
      partOf = [ "sensr-agent.service" ];
      unitConfig.ConditionPathExists = "${runtimeDir}/kea/kea-dhcp4.conf";
      serviceConfig = commonHardening // {
        ExecStartPre = "${kea}/bin/kea-dhcp4 -t ${runtimeDir}/kea/kea-dhcp4.conf";
        ExecStart = "${kea}/bin/kea-dhcp4 -c ${runtimeDir}/kea/kea-dhcp4.conf";
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
        Restart = "on-failure";
        DynamicUser = true;
        # Kea refuses a control-socket directory looser than 0750
        StateDirectory = "kea";
        StateDirectoryMode = "0750";
        RuntimeDirectory = "kea";
        RuntimeDirectoryMode = "0750";
        AmbientCapabilities = [
          "CAP_NET_BIND_SERVICE"
          "CAP_NET_RAW"
        ];
        CapabilityBoundingSet = [
          "CAP_NET_BIND_SERVICE"
          "CAP_NET_RAW"
        ];
        ProtectSystem = "strict";
        UMask = "0022";
      };
    };

    systemd.services.sensr-unbound = {
      description = "Unbound DNS resolver (config rendered by sensr)";
      after = [ "sensr-net.target" ];
      partOf = [ "sensr-agent.service" ];
      unitConfig.ConditionPathExists = "${runtimeDir}/unbound/unbound.conf";
      serviceConfig = commonHardening // {
        ExecStartPre = [
          # The DNSSEC root anchor lives in the state directory. Seed it from
          # the closure's copy (dns-root-data) when missing; Unbound keeps it
          # current itself (RFC 5011). Not unbound-anchor: without a route
          # to the internet it waits for its fetch to time out, about 5 s
          # of every first boot, and the agent's boot apply waits with it.
          "${pkgs.writeShellScript "sensr-unbound-anchor" ''
            if [ ! -s /var/lib/unbound/root.key ]; then
              ${pkgs.coreutils}/bin/install -m 0644 ${pkgs.dns-root-data}/root.key /var/lib/unbound/root.key
            fi
          ''}"
          "${unboundPkg}/bin/unbound-checkconf ${runtimeDir}/unbound/unbound.conf"
        ];
        ExecStart = "${unboundPkg}/bin/unbound -d -p -c ${runtimeDir}/unbound/unbound.conf";
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
        Restart = "on-failure";
        DynamicUser = true;
        StateDirectory = "unbound";
        RuntimeDirectory = "unbound";
        # dnstap socket of sensr-insight (/run/sensr-insight/dnstap.sock,
        # group sensr-dnstap, mode 0660). Unix sockets are not restricted
        # here (no RestrictAddressFamilies) and ProtectSystem=strict only
        # makes the path read-only, which connect() does not need.
        SupplementaryGroups = [ "sensr-dnstap" ];
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
        ProtectSystem = "strict";
        UMask = "0022";
      };
    };

    # Suricata (Services > Intrusion Detection). Config, arguments, HOME_NET
    # and rule lists are rendered into /run/sensr/suricata by the agent.
    systemd.services.sensr-suricata = {
      description = "Suricata IDS/IPS (config rendered by sensr)";
      after = [ "sensr-net.target" ];
      partOf = [ "sensr-agent.service" ];
      unitConfig.ConditionPathExists = "${runtimeDir}/suricata/suricata.yaml";
      serviceConfig = commonHardening // {
        ExecStartPre = suricataSeed;
        ExecStart = suricataStart;
        # a rule reload re-reads vars.yaml (HOME_NET), threshold.config and
        # the rules; capture changes need a restart
        ExecReload = "${pkgs.coreutils}/bin/kill -USR2 $MAINPID";
        Restart = "on-failure";
        RestartSec = 5;
        User = "suricata";
        Group = "suricata";
        StateDirectory = "suricata";
        StateDirectoryMode = "0750";
        LogsDirectory = "suricata";
        LogsDirectoryMode = "0750";
        RuntimeDirectory = "suricata";
        UMask = "0027";
        AmbientCapabilities = [
          "CAP_NET_ADMIN"
          "CAP_NET_RAW"
          "CAP_SYS_NICE"
          "CAP_IPC_LOCK"
        ];
        CapabilityBoundingSet = [
          "CAP_NET_ADMIN"
          "CAP_NET_RAW"
          "CAP_SYS_NICE"
          "CAP_IPC_LOCK"
        ];
        # PCRE2's JIT needs writable+executable pages
        MemoryDenyWriteExecute = false;
        ProtectSystem = "strict";
        PrivateDevices = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_NETLINK"
          "AF_PACKET"
          "AF_INET"
          "AF_INET6"
        ];
      };
    };

    # A rule reload for files Suricata re-reads (the agent restarts this).
    systemd.services.sensr-suricata-reload = {
      description = "Reload Suricata's rules if it runs";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${config.systemd.package}/bin/systemctl try-reload-or-restart sensr-suricata.service";
      };
    };

    # Downloads rules with suricata-update, then reloads Suricata. Started by
    # the agent when the rule lists change (through the trigger, so an apply
    # never waits for a download) and daily by the timer.
    systemd.services.sensr-suricata-update = {
      description = "Download Suricata rules (lists rendered by sensr)";
      wants = [ "network-online.target" ];
      after = [
        "network-online.target"
        "sensr-net.target"
      ];
      unitConfig.ConditionPathExists = "${runtimeDir}/suricata/update.args";
      startLimitIntervalSec = 0;
      path = [ suricata ];
      serviceConfig = commonHardening // {
        Type = "oneshot";
        ExecStartPre = suricataSeed;
        ExecStart = suricataUpdate;
        ExecStartPost = "+${config.systemd.package}/bin/systemctl try-reload-or-restart sensr-suricata.service";
        User = "suricata";
        Group = "suricata";
        StateDirectory = "suricata";
        StateDirectoryMode = "0750";
        TimeoutStartSec = "15min";
        # no network yet, a mirror down: try again instead of waiting a day
        Restart = "on-failure";
        RestartSec = "2min";
        ProtectSystem = "strict";
        PrivateDevices = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
      };
    };
    systemd.services.sensr-suricata-update-trigger = {
      description = "Start a Suricata rule download in the background";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${config.systemd.package}/bin/systemctl start --no-block sensr-suricata-update.service";
      };
    };
    # The agent sets the schedule (ids.updates) with a runtime drop-in and
    # starts the timer; the default here only keeps the unit valid.
    systemd.timers.sensr-suricata-update = {
      description = "Daily Suricata rule download";
      timerConfig = {
        OnCalendar = "*-*-* 04:00:00";
        Persistent = true;
      };
    };

    services.openssh = mkIf cfg.ssh.enable {
      enable = true;
      # sensr owns the packet filter (and networking.firewall is off).
      openFirewall = false;
      settings = {
        PasswordAuthentication = false;
        KbdInteractiveAuthentication = false;
        PermitRootLogin = "prohibit-password";
      };
      authorizedKeysFiles = [ "/run/sensr/ssh/authorized_keys/%u" ];
    };
    # Stopgap until the agent imports the seed's authorized_keys into the
    # config: give root the seed's keys at boot, unless the agent has
    # already rendered keys for root.
    systemd.services.sensr-seed-ssh-keys = mkIf cfg.ssh.enable {
      description = "SSH keys for root from the seed folder";
      wantedBy = [ "multi-user.target" ];
      before = [ "sshd.service" ];
      after = [ "local-fs.target" ];
      unitConfig = {
        RequiresMountsFor = cfg.seedDir;
        ConditionPathExists = "${cfg.seedDir}/authorized_keys";
      };
      serviceConfig = {
        Type = "oneshot";
        ExecStart = pkgs.writeShellScript "sensr-seed-ssh-keys" ''
          set -eu
          d=/run/sensr/ssh/authorized_keys
          mkdir -p -m 0755 /run/sensr/ssh "$d"
          if [ ! -s "$d/root" ]; then
            ${pkgs.coreutils}/bin/install -m 0644 ${cfg.seedDir}/authorized_keys "$d/root"
          fi
        '';
      };
    };

    # Time: ntpd-rs owns the clock (OPNsense runs ntpd whenever time servers
    # are set); a second NTP client would fight it.
    services.timesyncd.enable = false;
    systemd.services.systemd-timedated.environment.SYSTEMD_TIMEDATED_NTP_SERVICES =
      "sensr-ntpd.service";
    systemd.services.sensr-ntpd = {
      description = "ntpd-rs NTP client and server (config rendered by sensr)";
      after = [ "sensr-net.target" ];
      partOf = [ "sensr-agent.service" ];
      unitConfig.ConditionPathExists = "${runtimeDir}/ntp/ntp.toml";
      serviceConfig = {
        ExecStartPre = "${cfg.ntp.package}/bin/ntp-ctl validate -c ${runtimeDir}/ntp/ntp.toml";
        ExecStart = "${cfg.ntp.package}/bin/ntp-daemon --config ${runtimeDir}/ntp/ntp.toml";
        Restart = "on-failure";
        RestartSec = "10s";
        DynamicUser = true;
        RuntimeDirectory = "ntpd-rs";
        # The clock is the point (no ProtectClock); port 123 for clients.
        AmbientCapabilities = [
          "CAP_SYS_TIME"
          "CAP_NET_BIND_SERVICE"
        ];
        CapabilityBoundingSet = [
          "CAP_SYS_TIME"
          "CAP_NET_BIND_SERVICE"
        ];
        NoNewPrivileges = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        PrivateTmp = true;
        ProcSubset = "pid";
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
          "AF_NETLINK"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "@resources"
          "@network-io"
          "@clock"
        ];
        UMask = "0022";
      };
    };

    # sensr-dns (crates/sensr-dns): blocklists compiled into Unbound local
    # zones, DHCP leases registered as names, resolver counters for the UI.
    # It reads ${runtimeDir}/unbound/sensr-dns.json (rendered with
    # unbound.conf) and writes the include files unbound.conf globs for in
    # /var/lib/sensr-dns, then updates the running resolver with
    # unbound-control. Root: it reads Kea's lease file (Kea's private state
    # directory) and talks to Unbound's control socket.
    systemd.services.sensr-dnsbl = {
      description = "sensr DNS blocklist refresh";
      after = [
        "network-online.target"
        "sensr-unbound.service"
      ];
      wants = [ "network-online.target" ];
      unitConfig.ConditionPathExists = "${runtimeDir}/unbound/sensr-dns.json";
      path = [ unboundPkg ];
      serviceConfig = commonHardening // {
        Type = "oneshot";
        ExecStart = "${cfg.package}/bin/sensr-dns blocklist-update";
        # A first download that fails (typically racing the WAN at boot)
        # exits non-zero: retry instead of waiting for the hourly timer.
        Restart = "on-failure";
        RestartSec = "2min";
        StateDirectory = "sensr-dns";
        StateDirectoryMode = "0755";
        UMask = "0022";
        ProtectSystem = "strict";
        # Compiling 1.7 M names takes a few hundred MB for a few seconds.
        MemoryMax = "1G";
        Nice = 10;
      };
    };
    # The job decides which lists are due (each policy's refresh interval);
    # the timer only wakes it, and a new configuration starts it at once.
    systemd.timers.sensr-dnsbl = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "1min";
        OnUnitActiveSec = "1h";
        RandomizedDelaySec = "5min";
      };
    };
    systemd.paths.sensr-dnsbl = {
      wantedBy = [ "multi-user.target" ];
      pathConfig.PathChanged = "${runtimeDir}/unbound/sensr-dns.json";
    };
    systemd.services.sensr-dns-watch = {
      description = "sensr DHCP lease registration and resolver statistics";
      wantedBy = [ "multi-user.target" ];
      after = [
        "sensr-unbound.service"
        "sensr-kea-dhcp4.service"
      ];
      unitConfig.ConditionPathExists = "${runtimeDir}/unbound/sensr-dns.json";
      path = [ unboundPkg ];
      serviceConfig = commonHardening // {
        ExecStart = "${cfg.package}/bin/sensr-dns watch";
        Restart = "always";
        RestartSec = 5;
        StateDirectory = "sensr-dns";
        StateDirectoryMode = "0755";
        RuntimeDirectory = "sensr-dns";
        RuntimeDirectoryMode = "0755";
        UMask = "0022";
        ProtectSystem = "strict";
      };
    };

    # Traffic accounting and IDS alert storage (Reporting > Insight,
    # Intrusion Detection > Alerts). The agent loads the accounting table and
    # writes /run/sensr/insight/insight.json; the databases are group sensr
    # so sensr-api can read them.
    systemd.services.sensr-insight = {
      description = "sensr traffic insight and IDS alert storage";
      after = [ "sensr-net.target" ];
      partOf = [ "sensr-agent.service" ];
      unitConfig.ConditionPathExists = "${runtimeDir}/insight/insight.json";
      serviceConfig = commonHardening // {
        ExecStart = lib.escapeShellArgs [
          "${cfg.package}/bin/sensr-insight"
          "--config"
          "${runtimeDir}/insight/insight.json"
          "--nft"
          "${pkgs.nftables}/bin/nft"
          # the neighbour table (client address -> MAC for DNS activity)
          "--ip"
          "${pkgs.iproute2}/bin/ip"
        ];
        Restart = "on-failure";
        RestartSec = 5;
        User = "sensr-insight";
        Group = "sensr";
        SupplementaryGroups = [
          "suricata"
          "sensr-dnstap"
        ];
        # /run/sensr-insight holds the dnstap socket Unbound connects to.
        # systemd creates it as sensr-insight:sensr; Unbound is not in group
        # sensr, so ExecStartPre regroups it to sensr-dnstap (0750: insight
        # rwx, Unbound r-x to traverse, nobody else). "+" runs it unsandboxed
        # as root, after systemd has (re)created the directory. The socket
        # itself is created 0660 group sensr-dnstap by sensr-insight.
        RuntimeDirectory = "sensr-insight";
        RuntimeDirectoryMode = "0750";
        ExecStartPre = "+${pkgs.coreutils}/bin/chgrp sensr-dnstap /run/sensr-insight";
        StateDirectory = "sensr-insight";
        StateDirectoryMode = "0750";
        UMask = "0027";
        # listing the accounting table
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        ProtectSystem = "strict";
        PrivateDevices = true;
        ProtectKernelTunables = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_NETLINK"
        ];
        # small and steady: a lookup in the kernel per packet, a read every
        # few seconds here
        Nice = 5;
        MemoryMax = "256M";
      };
    };

    # Runtime guard (Services > Runtime Guard). The agent writes
    # /run/sensr/guard/guard.json and restarts the unit when it changes. Root
    # with the capabilities BPF LSM programs need; the programs are not
    # pinned, so they live and die with the process (fail open), and systemd
    # brings it back within a second. Exit status 78 is a refusal (kernel
    # lockdown is confidentiality): restarting would not help.
    systemd.services.sensr-guard = {
      description = "sensr runtime guard (eBPF LSM)";
      partOf = [ "sensr-agent.service" ];
      unitConfig.ConditionPathExists = "${runtimeDir}/guard/guard.json";
      # systemctl is-active boot-complete.target (module-load alerts start
      # once boot is complete)
      path = [ config.systemd.package ];
      serviceConfig = commonHardening // {
        ExecStart = lib.escapeShellArgs [
          "${cfg.package}/bin/sensr-guard"
          "--config"
          "${runtimeDir}/guard/guard.json"
          "--state"
          "/var/lib/sensr-guard"
          "--socket"
          "/run/sensr-guard/guard.sock"
          "--builtin"
          "${pkgs.sensr-guard-bpf}/share/sensr-guard/packs"
          "--keys"
          "${pkgs.sensr-guard-keys}/share/sensr-guard/keys"
        ];
        Restart = "always";
        RestartSec = 1;
        RestartPreventExitStatus = 78;
        User = "root";
        Group = "sensr";
        # systemd creates both root:sensr 0750: group sensr (sensr-api, the
        # CLI) traverses /run/sensr-guard to the socket, which sensr-guard
        # makes 0660, and reads events.db (0640 by the umask).
        RuntimeDirectory = "sensr-guard";
        RuntimeDirectoryMode = "0750";
        StateDirectory = "sensr-guard";
        StateDirectoryMode = "0750";
        UMask = "0027";
        # loading and attaching BPF LSM programs (CAP_SYS_ADMIN for the
        # attach), and the maps' locked memory
        CapabilityBoundingSet = [
          "CAP_BPF"
          "CAP_PERFMON"
          "CAP_SYS_ADMIN"
          "CAP_SYS_RESOURCE"
        ];
        ProtectSystem = "strict";
        ReadWritePaths = [ "/var/lib/sensr-guard" ];
        PrivateDevices = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
        MemoryMax = "256M";
      };
    };

    # eve.json grows with every alert; the alerts live in alerts.db.
    services.logrotate.settings.sensr-suricata = {
      files = [ "/var/log/suricata/*.json" ];
      frequency = "daily";
      maxsize = "50M";
      rotate = 3;
      compress = true;
      delaycompress = true;
      missingok = true;
      notifempty = true;
      su = "suricata suricata";
      postrotate = "${config.systemd.package}/bin/systemctl kill -s HUP sensr-suricata.service || true";
    };

    # The seed folder explains itself to whoever mounts the card on a laptop
    # (PLAN §6: every image's FAT partition has sensr/README.txt).
    systemd.services.sensr-seed-readme = {
      description = "Keep README.txt in the sensr seed folder current";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      unitConfig.ConditionPathIsDirectory = builtins.dirOf cfg.seedDir;
      serviceConfig = {
        Type = "oneshot";
        ExecStart = pkgs.writeShellScript "sensr-seed-readme" ''
          set -eu
          mkdir -p ${cfg.seedDir}
          if ! ${pkgs.diffutils}/bin/cmp -s ${seedReadme} ${cfg.seedDir}/README.txt; then
            cp ${seedReadme} ${cfg.seedDir}/README.txt.tmp
            mv ${cfg.seedDir}/README.txt.tmp ${cfg.seedDir}/README.txt
          fi
        '';
      };
    };

    # The installer's safety net (PLAN §6, 06 §1 L4): while
    # <seed>/reboot-after-minutes exists, reboot that many minutes after
    # every boot. On a Pi trial boot that returns to the previous system.
    systemd.services.sensr-reboot-after = {
      description = "Reboot N minutes after boot while the seed folder asks for it";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      unitConfig = {
        RequiresMountsFor = cfg.seedDir;
        ConditionPathExists = "${cfg.seedDir}/reboot-after-minutes";
      };
      serviceConfig.ExecStart = pkgs.writeShellScript "sensr-reboot-after" ''
        f=${cfg.seedDir}/reboot-after-minutes
        n=$(head -c 16 "$f" | tr -dc 0-9)
        [ -n "$n" ] || { echo "$f does not hold a number of minutes"; exit 0; }
        echo "rebooting in $n minutes unless $f is deleted"
        sleep $((n * 60))
        if [ -e "$f" ]; then
          echo "$f still exists: rebooting"
          ${config.systemd.package}/bin/systemctl reboot
        fi
      '';
    };

    boot.initrd.systemd.targets.initrd.unitConfig = {
      JobTimeoutSec = cfg.initrdTimeoutSec;
      JobTimeoutAction = "reboot-force";
    };

    # A trial boot (sensr.trial=1 on the kernel command line, from the trial
    # installer's cmdline.txt; nix/pi5/trial-health.sh): detected first, so
    # PID 1 owns the hard deadline before anything else runs; then the
    # self-health gate and the live log stream, with a trial-health.env in
    # the seed folder.
    systemd.services.sensr-trial-detect = {
      description = "Trial boot: detect it, arm the hard deadline";
      wantedBy = [ "sysinit.target" ];
      before = [
        "sysinit.target"
        "sensr-trial-health.service"
        "sensr-trial-logstream.service"
      ];
      unitConfig = {
        DefaultDependencies = false;
        ConditionKernelCommandLine = "sensr.trial=1";
      };
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${lib.getExe trialHealth} detect";
      };
    };
    # A trial boot that was armed by copying the dormant boot config over
    # config.txt (see trial-health.sh's revert) must not become the default
    # OS: count its boots down before anything else can hang and hand the boot
    # back to the installed OS when they run out, so a mute trial can never
    # trap the box again.
    systemd.services.sensr-trial-revert = {
      description = "Trial boot: hand the next boot back to the installed OS";
      wantedBy = [ "sysinit.target" ];
      before = [
        "sysinit.target"
        "sensr-trial-health.service"
      ];
      unitConfig = {
        DefaultDependencies = false;
        ConditionKernelCommandLine = "sensr.trial=1";
      };
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${lib.getExe trialHealth} revert";
      };
    };

    systemd.services.sensr-trial-health = {
      description = "Trial boot self-health gate (reboots to the previous OS on failure)";
      wantedBy = [ "multi-user.target" ];
      after = [
        "local-fs.target"
        "network-online.target"
        "sensr-agent.service"
      ];
      wants = [ "network-online.target" ];
      unitConfig = {
        ConditionPathExists = [
          "/run/sensr-trial/active"
          "${cfg.seedDir}/trial-health.env"
        ];
        RequiresMountsFor = cfg.seedDir;
      };
      serviceConfig.ExecStart = "${lib.getExe trialHealth} run";
    };
    systemd.services.sensr-trial-logstream = {
      description = "Trial boot: stream the journal over UDP";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      unitConfig = {
        ConditionPathExists = [
          "/run/sensr-trial/active"
          "${cfg.seedDir}/trial-health.env"
        ];
        RequiresMountsFor = cfg.seedDir;
      };
      serviceConfig = {
        ExecStart = "${lib.getExe trialHealth} stream";
        # no LOG_UDP: it exits cleanly and stays down
        Restart = "on-failure";
        RestartSec = "10s";
      };
    };

    systemd.services.sensr-selftest = mkIf cfg.selftest.enable {
      description = "sensr boot selftest (T-0391..T-0401)";
      wantedBy = [
        "multi-user.target"
        "boot-complete.target"
      ];
      requiredBy = [ "boot-complete.target" ];
      before = [ "boot-complete.target" ];
      after = [
        "sensr-agent.service"
        "sensr-net.target"
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = lib.getExe selftest;
        RuntimeDirectory = "sensr-selftest";
        RuntimeDirectoryPreserve = "yes";
        StandardOutput = "journal+console";
      };
    };

    # Upgrades are nix copies of prebuilt closures (06 §2.4 item 3); the box
    # never evaluates nixpkgs, but it needs the store tools.
    nix.settings.experimental-features = [
      "nix-command"
      "flakes"
    ];
  };
}
