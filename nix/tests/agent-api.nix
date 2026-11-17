# sensr-agent, sensr-api and the sensr CLI as the real services: commit,
# commit-confirm with automatic rollback (also across an agent restart),
# API authentication, ACLs and the OPNsense compat reads, plus latency.
{
  pkgs,
  sensrModules,
}:
let
  # bcrypt of "opnsense", OPNsense's factory default root password (the hash
  # in upstream's ACL test fixture).
  rootHash = "$2y$10$YRVoF4SgskIsrXOvOQjGieB9XqHPRra9R7d80B3BZdbY/j21TwBfS";
  # The typed document's shape: UUID-keyed users and groups, membership
  # listed on the user.
  users = builtins.toJSON {
    "7a0c1d2e-0000-4000-8000-000000000001" = {
      name = "root";
      uid = 0;
      password_hash = rootHash;
      groups = [ "admins" ];
    };
    "7a0c1d2e-0000-4000-8000-000000000002" = {
      name = "viewer";
      uid = 2000;
      password_hash = rootHash;
      groups = [ "viewers" ];
    };
  };
  groups = builtins.toJSON {
    "7a0c1d2e-0000-4000-8000-0000000000a1" = {
      name = "admins";
      gid = 1999;
      privileges = [ "page-all" ];
    };
    "7a0c1d2e-0000-4000-8000-0000000000a2" = {
      name = "viewers";
      gid = 2000;
      privileges = [ "page-sensr-status" ];
    };
  };
in
pkgs.testers.runNixOSTest {
  name = "sensr-agent-api";
  # A LAN client, to see the web GUI's interface restriction from outside.
  nodes.client =
    { ... }:
    {
      environment.systemPackages = [ pkgs.curl ];
    };
  nodes.machine =
    { ... }:
    {
      imports = sensrModules ++ [ ../images/common.nix ];
      virtualisation.memorySize = 1024;
      users.users.root.hashedPassword = pkgs.lib.mkForce null;
      services.sensr.seedDir = "/boot/sensr";
      systemd.tmpfiles.rules = [ "d /boot 0755 root root -" ];
      environment.etc."sensr-test/users.json".text = users;
      environment.etc."sensr-test/groups.json".text = groups;
      environment.systemPackages = [
        pkgs.curl
        pkgs.jq
        pkgs.sqlite
        pkgs.openssl
      ];
    };

  testScript = ''
    import json

    def applied(path):
        return machine.succeed(f"sensr config get {path} --source applied").strip()

    machine.wait_for_unit("sensr-agent.service")
    machine.wait_for_unit("sensr-api.service")

    with subtest("socket is 0660 root:sensr, agent is a notify service"):
        machine.succeed("stat -c '%a %U %G' /run/sensr/agent.sock | grep -qx '660 root sensr'")
        machine.succeed("systemctl show -P Type sensr-agent | grep -qx notify")

    with subtest("set, diff, commit"):
        machine.succeed("sensr config set system.hostname base")
        machine.succeed("sensr config diff | grep -q '+    \"hostname\": \"base\"'")
        machine.succeed("sensr config commit -m base")
        assert applied("system.hostname") == "base"
        # first boot may have committed the MAC pins before this: count from here
        base = json.loads(machine.succeed("sensr status --json"))["head"]["id"]

    with subtest("commit-confirm: confirmed in time"):
        machine.succeed("sensr config set system.hostname kept")
        machine.succeed("sensr config commit --confirm 60 | grep -q provisional")
        machine.succeed(f"sensr status | grep -q 'rolls back to {base}'")
        machine.succeed(f"sensr config confirm | grep -q 'revision {base + 1} confirmed'")
        assert applied("system.hostname") == "kept"

    with subtest("commit-confirm: timeout rolls back"):
        machine.succeed("sensr config set system.hostname risky")
        machine.succeed("sensr config commit --confirm 2")
        assert applied("system.hostname") == "risky"
        machine.wait_until_succeeds("sensr status --json | jq -e '.pending_confirm == null'", timeout=30)
        assert applied("system.hostname") == "kept"
        machine.succeed("sensr config history | grep -q 'commit-confirm timeout'")

    with subtest("commit-confirm: an agent restart while pending rolls back"):
        machine.succeed("sensr config set system.hostname restart-me")
        machine.succeed("sensr config commit --confirm 600")
        machine.succeed("systemctl restart sensr-agent")
        machine.wait_until_succeeds("sensr status")
        assert applied("system.hostname") == "kept"
        machine.succeed("sensr status --json | jq -e '.pending_confirm == null'")
        machine.succeed("sensr config history | grep -q 'agent restarted'")

    with subtest("history survives the restart (persistent store)"):
        out = json.loads(machine.succeed("sensr config history --json"))
        # Revision 1 is the factory document.
        assert len(out) >= 7, out

    with subtest("one store: applied revision and confirm state live in config.db"):
        machine.fail("test -e /var/lib/sensr/agent-state.json")
        machine.fail("test -e /var/lib/sensr/revisions")
        machine.succeed("sqlite3 /var/lib/sensr/config.db \"select value from state where key = 'applied'\" | grep -qx '[0-9]*'")

    with subtest("users for the API; the password hash is never returned"):
        # A user may only join groups that exist: groups first.
        machine.fail('sensr config set system.users --json "$(cat /etc/sensr-test/users.json)"')
        machine.succeed('sensr config set system.groups --json "$(cat /etc/sensr-test/groups.json)"')
        machine.succeed('sensr config set system.users --json "$(cat /etc/sensr-test/users.json)"')
        machine.succeed("sensr config commit -m users")
        machine.fail("sensr config get system.users | grep -q YRVoF4")
        machine.fail("grep -q YRVoF4 /var/lib/sensr/config.json")

    with subtest("secrets are encrypted at rest under a root-only key"):
        machine.succeed("stat -c '%a %U' /var/lib/sensr/secrets.key | grep -qx '600 root'")
        rows = machine.succeed("sqlite3 /var/lib/sensr/config.db 'select value from secrets'").split()
        assert rows and all(r.startswith("enc1:") for r in rows), rows
        machine.fail("sqlite3 /var/lib/sensr/config.db .dump | grep -q YRVoF4")

    with subtest("schema violations are rejected on write and store nothing"):
        out = machine.fail("sensr config set system.hostname 'not a hostname' 2>&1")
        print(out)
        machine.succeed("sensr status --json | jq -e '.candidate_dirty == false'")

    api = "https://localhost"
    with subtest("HTTPS with the certificate from the local CA (created at first boot)"):
        machine.succeed("stat -c '%a %U' /var/lib/sensr/tls/ca.key /var/lib/sensr/tls/server.key | grep -c '^600 root$' | grep -qx 2")
        machine.succeed("cp /var/lib/sensr/tls/ca.pem /tmp/ca.pem")
        machine.wait_until_succeeds(f"curl --cacert /tmp/ca.pem -s -o /dev/null {api}/api/v1/status", timeout=30)
        # Without the CA, curl refuses the certificate (exit 60).
        rc, _ = machine.execute(f"curl -s -o /dev/null {api}/api/v1/status")
        assert rc == 60, rc
        out = machine.succeed("openssl s_client -connect localhost:443 -servername localhost </dev/null 2>/dev/null | openssl x509 -noout -issuer -ext subjectAltName")
        print(out)
        assert "sensr local CA" in out, out

    with subtest("HTTP on port 80 redirects to HTTPS"):
        out = machine.succeed("curl -s -o /dev/null -w '%{http_code} %{redirect_url}' 'http://localhost/ui/login?x=1'")
        assert out == "308 https://localhost/ui/login?x=1", out
    with subtest("API authenticates and enforces ACLs"):
        machine.succeed(f"curl --cacert /tmp/ca.pem -s -o /dev/null -w '%{{http_code}}' {api}/api/v1/status | grep -qx 401")
        machine.succeed(f"curl --cacert /tmp/ca.pem -s -o /dev/null -w '%{{http_code}}' -u root:wrong {api}/api/v1/status | grep -qx 401")
        machine.succeed(f"curl --cacert /tmp/ca.pem -sf -u root:opnsense {api}/api/v1/status | jq -e '.applied >= 8'")
        machine.succeed(f"curl --cacert /tmp/ca.pem -sf -u viewer:opnsense {api}/api/v1/status >/dev/null")
        machine.succeed(f"curl --cacert /tmp/ca.pem -s -o /dev/null -w '%{{http_code}}' -u viewer:opnsense {api}/api/v1/config/doc | grep -qx 403")

    with subtest("API writes go through commit"):
        machine.succeed(f"curl --cacert /tmp/ca.pem -sf -u root:opnsense -X PUT -H 'Content-Type: application/json' -d '\"from-api\"' {api}/api/v1/config/doc/system/hostname")
        out = json.loads(machine.succeed(f"curl --cacert /tmp/ca.pem -sf -u root:opnsense -X POST -H 'Content-Type: application/json' -d '{{\"description\": \"api\"}}' {api}/api/v1/config/commit"))
        assert out["revision"]["username"] == "root@ui", out
        assert applied("system.hostname") == "from-api"

    with subtest("OPNsense compat reads"):
        machine.succeed(f"curl --cacert /tmp/ca.pem -sf -u root:opnsense {api}/api/core/firmware/info | jq -e '.product.product_name == \"sensr\"'")
        machine.succeed(f"curl --cacert /tmp/ca.pem -sf -u root:opnsense {api}/api/interfaces/overview/interfaces_info | jq -e '.rows | type == \"array\"'")
        machine.succeed(f"curl --cacert /tmp/ca.pem -sf -u root:opnsense {api}/api/firewall/alias/search_item | jq -e '.total == 0'")

    with subtest("duplicate alias names are rejected on the real stack"):
        alias = lambda name: json.dumps({"name": name, "content": {"type": "port", "entries": ["443"]}})
        a = "firewall.aliases.0b5e0000-0000-4000-8000-00000000000a"
        b = "0b5e0000-0000-4000-8000-00000000000b"
        web = alias("web")
        machine.succeed(f"sensr config set {a} --json '{web}'")
        machine.succeed("sensr config commit -m alias")
        code = machine.succeed(
            f"curl --cacert /tmp/ca.pem -s -o /tmp/dup.json -w '%{{http_code}}' -u root:opnsense -X PUT -H 'Content-Type: application/json'"
            f" -d '{web}' {api}/api/v1/config/doc/firewall/aliases/{b}"
        )
        print(machine.succeed("cat /tmp/dup.json"))
        assert code == "422", code
        machine.succeed("jq -e '.validations | keys | any(contains(\"firewall.aliases\"))' /tmp/dup.json")
        machine.succeed(f"curl --cacert /tmp/ca.pem -sf -u root:opnsense {api}/api/firewall/alias/search_item | jq -e '.total == 1'")

    with subtest("the listener follows system.webgui"):
        machine.succeed("sensr config set system.webgui --json '{\"port\": \"8443\"}'")
        machine.succeed("sensr config commit -m 'web GUI on 8443'")
        machine.wait_until_succeeds("curl --cacert /tmp/ca.pem -sf -u root:opnsense https://localhost:8443/api/v1/status", timeout=30)
        machine.wait_until_fails("curl --cacert /tmp/ca.pem -s -o /dev/null https://localhost/api/v1/status", timeout=30)
        out = machine.succeed("curl -s -o /dev/null -w '%{redirect_url}' http://localhost/")
        assert out == "https://localhost:8443/", out

        # first boot binds LAN to its card by MAC and names it after the role
        lan_dev = machine.succeed("sensr config get interfaces.lan.device --source applied").strip()
        lan = machine.succeed(f"ip -4 -o addr show dev {lan_dev} | awk '{{print $4}}' | cut -d/ -f1").strip()
        probe = f"curl -sk -o /dev/null -w '%{{http_code}}' --connect-timeout 3 https://{lan}:8443/api/v1/status"
        client.wait_for_unit("multi-user.target")
        client.succeed(f"{probe} | grep -qx 401")
        # Only WAN: a LAN client is refused, the box itself still gets in.
        machine.succeed("sensr config set system.webgui.interfaces --json '[\"wan\"]'")
        machine.succeed("sensr config commit -m 'web GUI on WAN only'")
        client.wait_until_fails(probe + " | grep -qx 401", timeout=30)
        machine.succeed("curl --cacert /tmp/ca.pem -sf -u root:opnsense https://localhost:8443/api/v1/status >/dev/null")
        machine.succeed("sensr config set system.webgui.interfaces --json '[\"lan\"]'")
        machine.succeed("sensr config commit -m 'web GUI on LAN'")
        client.wait_until_succeeds(f"{probe} | grep -qx 401", timeout=30)
        machine.succeed("sensr config delete system.webgui.interfaces")
        machine.succeed("sensr config delete system.webgui.port")
        machine.succeed("sensr config commit -m 'web GUI default'")
        machine.wait_until_succeeds(f"curl --cacert /tmp/ca.pem -sf -o /dev/null -u root:opnsense {api}/api/v1/status", timeout=30)

    with subtest("latency"):
        # 200 CLI round trips (process start included).
        cli = float(machine.succeed("s=$(date +%s%N); for i in $(seq 200); do sensr config get system.hostname >/dev/null; done; e=$(date +%s%N); echo $(( (e - s) / 200000 ))").strip()) / 1000
        # 200 API reads on one keep-alive connection (credential cache warm).
        urls = " ".join([f"{api}/api/v1/config/doc/system/hostname"] * 200)
        out = machine.succeed(f"curl --cacert /tmp/ca.pem -s -u root:opnsense -w '\\nT=%{{time_total}}\\n' {urls}")
        times = [float(line[2:]) for line in out.splitlines() if line.startswith("T=")]
        assert len(times) == 200, len(times)
        times.sort()
        print(f"LATENCY cli_round_trip_ms={cli:.2f} api_read_p50_ms={times[100]*1000:.3f} api_read_p95_ms={times[190]*1000:.3f}")
        assert times[100] < 0.05, times[100]
  '';
}
