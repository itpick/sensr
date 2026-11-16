# A fresh sensr system boots: the units come up, the selftest passes and the
# config store answers (docs/PLAN.md §8 task 10; docs/research/03 §2.7).
#
# `parity` lists the checklist rows this test discharges (xtask parity scans
# nix/tests for them). Rows still pending in nix/pending.nix are asserted as
# "pending" instead.
{
  pkgs,
  sensrModules,
}:
let
  pending = import ../pending.nix;
  py = b: if b then "True" else "False";
  # parity: T-0387 T-0391 T-0392 T-0393 T-0397 T-0401
in
pkgs.testers.runNixOSTest {
  name = "sensr-boot-first-run";
  nodes.machine =
    { ... }:
    {
      imports = sensrModules ++ [ ../images/common.nix ];
      virtualisation.memorySize = 1024;
      # The test driver logs in as root with its own password.
      users.users.root.hashedPassword = pkgs.lib.mkForce null;
      # The image's first-boot seed folder; the test VM has no ESP, so /boot
      # is a plain directory.
      services.sensr.seedDir = "/boot/sensr";
      systemd.tmpfiles.rules = [ "d /boot 0755 root root -" ];
    };

  testScript = ''
    import json
    from datetime import timedelta

    PENDING = {
        "agentDaemon": ${py pending.agentDaemon},
        "apiDaemon": ${py pending.apiDaemon},
        "configGet": ${py pending.configGet},
    }

    def note_pending(what):
        print(f"PENDING: {what} (nix/pending.nix)")

    machine.wait_for_unit("multi-user.target")

    with subtest("selftest passes"):
        machine.wait_for_unit("sensr-selftest.service")
        result = json.loads(machine.succeed("cat /run/sensr-selftest/result.json"))
        print(json.dumps(result, indent=2))
        assert result["result"] == "pass", result
        status = {r["id"]: r["status"] for r in result["rows"]}
        for row in ["T-0391", "T-0392", "T-0393", "T-0397"]:
            assert status[row] == "pass", (row, status)
        if PENDING["configGet"]:
            assert status["T-0401"] == "pending", status
            note_pending("T-0401 sensr config get")
        else:
            assert status["T-0401"] == "pass", status

    with subtest("version.json describes this generation (T-0391, T-0393, T-0397)"):
        v = json.loads(machine.succeed("cat /etc/sensr/version.json"))
        assert v["product_id"] == "sensr", v
        assert machine.succeed("uname -r").strip() == v["kernel"], v
        machine.succeed(f"test -x {v['agent']} && test -x {v['api']} && test -x {v['cli']}")
        machine.succeed(f"nix-store -qR /run/current-system | grep -qxF {v['package']}")
        machine.succeed("readlink -e /run/current-system")

    with subtest("the selftest gates boot-complete.target"):
        # The target itself is only pulled in when systemd-boot booted a
        # counted entry (qcow-boot checks that); here, check the wiring.
        machine.succeed("systemctl show -P RequiredBy sensr-selftest | grep -qw boot-complete.target")
        machine.succeed("systemctl show -P Before sensr-selftest | grep -qw boot-complete.target")

    with subtest("sensr-agent"):
        if PENDING["agentDaemon"]:
            note_pending("sensr-agent as a daemon; checking the stub ran cleanly")
            machine.wait_until_succeeds(
                "systemctl show -P ExecMainStatus sensr-agent | grep -qx 0"
                " && systemctl show -P ExecMainStartTimestampMonotonic sensr-agent | grep -qv '^0$'"
            )
        else:
            try:
                machine.wait_for_unit("sensr-agent.service", timeout=timedelta(seconds=60))
            finally:
                print(machine.execute("systemctl status sensr-agent --no-pager; journalctl -b -u sensr-agent --no-pager | tail -n 40")[1])
            machine.wait_for_file("/run/sensr/agent.sock")
            machine.succeed("stat -c '%a %U %G' /run/sensr/agent.sock | grep -qx '660 root sensr'")
            # It survives a restart with its state (revisions on disk).
            machine.succeed("systemctl restart sensr-agent")
            machine.wait_for_unit("sensr-agent.service")
            machine.succeed("test -d /var/lib/sensr/revisions")
        # Hardening that must not regress, whatever the agent does.
        props = machine.succeed(
            "systemctl show -p User -p ProtectSystem -p NoNewPrivileges -p CapabilityBoundingSet sensr-agent"
        )
        print(props)
        assert "ProtectSystem=strict" in props, props
        assert "NoNewPrivileges=yes" in props, props
        assert "cap_sys_module" not in props, props
        machine.succeed("stat -c '%a' /var/lib/sensr | grep -qx 700")

    with subtest("sensr-api"):
        props = machine.succeed("systemctl show -p User -p SupplementaryGroups sensr-api")
        assert "User=sensr-api" in props, props
        assert "SupplementaryGroups=sensr" in props, props
        # The API process cannot see the store.
        machine.fail("runuser -u sensr-api -- ls /var/lib/sensr")
        if PENDING["apiDaemon"]:
            note_pending("sensr-api as a daemon; checking the stub ran cleanly")
            machine.wait_until_succeeds("systemctl show -P ExecMainStatus sensr-api | grep -qx 0")
        else:
            machine.wait_for_unit("sensr-api.service")

    with subtest("config get (T-0401)"):
        if PENDING["configGet"]:
            note_pending("T-0401")
        else:
            out = machine.succeed("sensr config get --json")
            assert isinstance(json.loads(out), dict), out

    with subtest("seed folder"):
        machine.succeed("grep -q 'first-boot seed folder' /boot/sensr/README.txt")

    with subtest("the packages the appliers drive are in the closure"):
        for tool in ["nft --version", "kea-dhcp4 -V", "unbound -V", "wg --version"]:
            machine.succeed(tool)
        # Daemon units exist but stay down until the agent renders a config.
        for unit in ["sensr-kea-dhcp4", "sensr-unbound"]:
            machine.succeed(f"systemctl cat {unit}.service")
            machine.fail(f"systemctl is-active {unit}.service")

    with subtest("nothing failed"):
        machine.succeed("test -z \"$(systemctl list-units --failed --no-legend)\" || (systemctl list-units --failed; false)")
  '';
}
