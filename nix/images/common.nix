# What every sensr image shares: the appliance profile on top of
# services.sensr. Board- and format-specific bits live in qcow.nix, pi5.nix.
{ lib, modulesPath, ... }:
{
  imports = [
    "${modulesPath}/profiles/minimal.nix"
    # No Perl in activation (userborn, etc overlay), and a build-time check
    # that none comes back.
    "${modulesPath}/profiles/perlless.nix"
  ];

  services.sensr.enable = true;
  # An image routes: the agent drives the appliers (checks.slice proves
  # them against the oracle). Tests that only need the store override it.
  services.sensr.applier = lib.mkDefault "slice";

  system.stateVersion = "26.11";
  # Weaker than mkDefault so test drivers and seeds can name the box.
  networking.hostName = lib.mkOverride 1200 "sensr";

  # A stage that hangs or panics reboots instead of waiting for a keyboard
  # nobody is at (vyos-pi PR #6 lesson): the initrd's emergency target
  # panics (boot.panic_on_fail) and the kernel reboots 10 s after a panic.
  boot.kernelParams = [
    "panic=10"
    "boot.panic_on_fail"
    # The factory document (no seed) names the first two NICs eth0 (WAN)
    # and eth1 (LAN), in enumeration order (PLAN §6). Until first boot
    # records NICs by MAC (the ifnames seed), keep the kernel's names.
    "net.ifnames=0"
  ];
  # PID 1 keeps a hardware watchdog fed when the board has one; a hang in
  # userspace then resets the box. Without a watchdog device this is a no-op.
  systemd.settings.Manager = {
    RuntimeWatchdogSec = "15s";
    RebootWatchdogSec = "2min";
  };

  # No interactive accounts until the seed provides one (PLAN §6: admin
  # password or authorized_keys from the seed folder).
  users.mutableUsers = false;
  users.users.root.hashedPassword = "!";
  # Deliberate: access comes from the seed folder at first boot, never from
  # a password baked into a published image.
  users.allowNoPasswordLogin = true;

  documentation.enable = false;

  # An appliance is upgraded by copying a prebuilt closure and switching to
  # it (06 §2.4 item 3); it never evaluates nixpkgs. That drops
  # nixos-rebuild (and Python), nixos-option, nixos-generate-config and the
  # pinned nixpkgs source from the image.
  system.disableInstallerTools = true;
  nixpkgs.flake.setNixPath = false;
  nixpkgs.flake.setFlakeRegistry = false;
  # Journald is the log store; keep it bounded on small cards.
  services.journald.settings.Journal.SystemMaxUse = "256M";
}
