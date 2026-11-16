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
  appliedPackages = with pkgs; [
    nftables
    kea
    unbound
    wireguard-tools
    iproute2
    conntrack-tools
    ethtool
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
            if sensr config get --json | jq -e 'type == "object"' >/dev/null; then
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
        type = types.str;
        default = "[::]:443";
        description = "Address sensr-api listens on ($SENSR_API_LISTEN).";
      };
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
    ];

    users.groups.sensr.gid = sensrGid;
    users.groups.sensr-api.gid = apiUid;
    users.users.sensr-api = {
      isSystemUser = true;
      uid = apiUid;
      group = "sensr-api";
      extraGroups = [ "sensr" ];
      description = "sensr API";
    };

    environment.systemPackages = [ cfg.package ] ++ appliedPackages;
    environment.etc."sensr/version.json".text = builtins.toJSON versionJson;

    environment.variables.SENSR_AGENT_SOCKET = socket;

    # networkd reads runtime config from here; the agent writes into it.
    systemd.tmpfiles.rules = [ "d /run/systemd/network 0755 root root -" ];

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
        # signalling them (KILL).
        CapabilityBoundingSet = [
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
          "-${cfg.seedDir}"
          "-/boot/firmware"
        ];
        # Per-interface sysctls (forwarding, rp_filter, accept_ra).
        ProtectKernelTunables = false;
        ProtectKernelLogs = true;
        ProtectHostname = false;
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
      after = [
        "sensr-agent.service"
        "sensr-net.target"
      ];
      wants = [ "sensr-agent.service" ];
      environment = {
        SENSR_AGENT_SOCKET = socket;
        SENSR_API_LISTEN = cfg.api.listen;
        RUST_LOG = "info";
      };
      serviceConfig = commonHardening // {
        Type = "exec";
        ExecStart = "${cfg.package}/bin/sensr-api";
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
          # the DNSSEC root anchor lives in the state directory; seed it from
          # unbound's built-in anchor (no network needed), "-": exit 1 means
          # "used the built-in anchor"
          "-${pkgs.unbound}/bin/unbound-anchor -a /var/lib/unbound/root.key"
          "${pkgs.unbound}/bin/unbound-checkconf ${runtimeDir}/unbound/unbound.conf"
        ];
        ExecStart = "${pkgs.unbound}/bin/unbound -d -p -c ${runtimeDir}/unbound/unbound.conf";
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
        Restart = "on-failure";
        DynamicUser = true;
        StateDirectory = "unbound";
        RuntimeDirectory = "unbound";
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
        ProtectSystem = "strict";
        UMask = "0022";
      };
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
