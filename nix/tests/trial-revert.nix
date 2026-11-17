# A trial boot always ends back on the previous OS, on its own.
#
# The Pi firmware's tryboot is a one-shot: whatever resets the board after
# the trial boot (a reboot, a panic, the watchdog), the next boot is the old
# OS. Here the test driver plays the firmware. QEMU runs with -no-reboot, so
# any reset or reboot ends the QEMU process; a trial boot gets
# "sensr.trial=1 sensr.trial.deadline=N" on its kernel command line, the
# next power-on gets none ("the previous OS"). Each scenario checks that the
# trial boot ends by itself, in time, and by the path it is meant to:
#
#   healthy run             PID 1's deadline timer
#   checks never pass       the health gate (a WAN address that never comes)
#   agent and gate hung     the deadline (independent of both)
#   PID 1 frozen            the hardware watchdog (i6300esb, systemd
#                           RuntimeWatchdogSec; CrashAction=freeze, so
#                           nothing else could reboot it)
#   kernel panic            panic=10
#   initrd hang             initrd.target's job timeout (reboot-force)
#
# On the Pi the firmware also starts the BCM2712 watchdog before the kernel
# (kernel_watchdog_timeout, early-watchdog in the device tree:
# nix/pi5/boot-files.nix checks it at build time), which QEMU cannot model.
{
  pkgs,
  sensrModules,
}:
let
  inherit (pkgs) lib;
in
pkgs.testers.runNixOSTest {
  name = "sensr-trial-revert";
  nodes.pi =
    { config, ... }:
    {
      imports = sensrModules ++ [ ../images/common.nix ];
      services.sensr.seedDir = "/boot/sensr";
      services.sensr.initrdTimeoutSec = 40;
      users.users.root.hashedPassword = lib.mkForce null;
      systemd.tmpfiles.rules = [ "d /boot/sensr 0755 root root -" ];
      # A frozen PID 1 must not reboot by itself: only the watchdog can.
      systemd.settings.Manager.CrashAction = "freeze";
      virtualisation.qemu.options = [
        "-device i6300esb"
        "-action watchdog=reset"
      ];
      boot.kernelModules = [ "i6300esb" ];
      # A stand-in for an initrd that hangs (a root that never appears, a
      # hung unit), only when the test asks for it.
      boot.initrd.systemd.extraBin.sleep = "${pkgs.coreutils}/bin/sleep";
      boot.initrd.systemd.services.test-initrd-hang = {
        wantedBy = [ "initrd.target" ];
        before = [ "initrd.target" ];
        unitConfig = {
          DefaultDependencies = false;
          ConditionKernelCommandLine = "sensr.test.initrd_hang=1";
        };
        serviceConfig = {
          Type = "oneshot";
          TimeoutStartSec = "infinity";
          ExecStart = "/bin/sleep infinity";
        };
      };
    };

  testScript = ''
    import os
    import time

    TRIAL = "sensr.trial=1 sensr.trial.deadline={}"


    def power_on(params):
        """The firmware: this power-on's kernel command line; any reset ends it."""
        os.environ["QEMU_KERNEL_PARAMS"] = params
        os.environ["QEMU_OPTS"] = "-no-reboot"
        pi.start()
        return time.monotonic()


    def ends_within(t0, lo, hi, what):
        pi.wait_for_shutdown()
        took = time.monotonic() - t0
        print(f"{what}: the trial boot ended after {took:.0f} s")
        assert lo <= took <= hi, f"{what}: ended after {took:.0f} s, want {lo}..{hi}"


    def previous_os():
        """The next power-on is the previous OS: no trial, no deadline."""
        power_on("")
        pi.wait_for_unit("multi-user.target")
        pi.succeed("test ! -e /run/sensr-trial/active")
        assert "sensr-trial-deadline" not in pi.succeed("systemctl list-timers --all --no-legend")
        pi.shutdown()


    def fire(cmd):
        # the command takes the box down with it; its shell may never answer
        try:
            pi.execute(cmd, check_return=False, timeout=10)
        except Exception as e:  # noqa: BLE001
            print(f"{cmd}: {e}")


    def health_env(text):
        pi.succeed(f"mkdir -p /boot/sensr && printf '%b' '{text}' > /boot/sensr/trial-health.env && sync")


    with subtest("the previous OS boots without a trial"):
        power_on("")
        pi.wait_for_unit("multi-user.target")
        pi.succeed("test ! -e /run/sensr-trial/active")
        health_env("")
        pi.shutdown()

    with subtest("healthy trial: the deadline reboots it"):
        t0 = power_on(TRIAL.format(45))
        pi.wait_for_unit("sensr-trial-detect.service")
        pi.succeed("test -e /run/sensr-trial/active")
        timers = pi.succeed("systemctl list-timers --all --no-legend")
        assert "sensr-trial-deadline.timer" in timers and "sensr-trial-deadline-force.timer" in timers, timers
        pi.fail("sensr-trial-health confirm")
        ends_within(t0, 40, 120, "healthy")
        previous_os()

    with subtest("checks never pass: the health gate reboots it before the deadline"):
        power_on("")
        pi.wait_for_unit("multi-user.target")
        health_env("TRIAL_GRACE_SECONDS=20\\nWAN_IP=198.51.100.7\\n")
        pi.shutdown()
        t0 = power_on(TRIAL.format(400))
        ends_within(t0, 15, 150, "checks fail")
        previous_os()
        power_on("")
        pi.wait_for_unit("multi-user.target")
        health_env("")
        pi.shutdown()

    with subtest("agent and gate hung: the deadline still reboots it"):
        t0 = power_on(TRIAL.format(60))
        pi.wait_for_unit("sensr-agent.service")
        pi.succeed("systemctl kill -s STOP sensr-agent.service sensr-trial-health.service || systemctl kill -s STOP sensr-agent.service")
        ends_within(t0, 55, 160, "agent hung")
        previous_os()

    with subtest("PID 1 frozen: the hardware watchdog resets it"):
        t0 = power_on(TRIAL.format(900))
        pi.wait_for_unit("multi-user.target")
        pi.succeed("test -e /dev/watchdog0")
        assert pi.succeed("systemctl show -p RuntimeWatchdogUSec --value").strip() not in ("0", "infinity")
        fire("kill -SEGV 1")
        ends_within(t0, 0, 200, "PID 1 frozen")
        previous_os()

    with subtest("kernel panic: panic=10 reboots it"):
        t0 = power_on(TRIAL.format(900))
        pi.wait_for_unit("multi-user.target")
        fire("echo c > /proc/sysrq-trigger")
        ends_within(t0, 0, 120, "kernel panic")
        previous_os()

    with subtest("initrd hang: initrd.target's job timeout reboots it"):
        t0 = power_on(TRIAL.format(900) + " sensr.test.initrd_hang=1")
        ends_within(t0, 35, 150, "initrd hang")
        previous_os()
  '';
}
