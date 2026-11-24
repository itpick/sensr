# The daily store cleanup (sensr-store-gc, nix/modules/updates.nix): it keeps
# the profile's active generation, the running and booted systems, every
# system the boot partition names, and the newest keepGenerations others;
# older generations and their closures go.
{
  pkgs,
  sensrModules,
}:
pkgs.testers.runNixOSTest {
  name = "sensr-store-gc";
  nodes.router =
    { lib, ... }:
    {
      imports = sensrModules ++ [ ../images/common.nix ];
      services.sensr.seedDir = "/boot/sensr";
      services.sensr.updates.keepGenerations = 3;
      services.sensr.updates.bootDir = "/var/lib/fake-firmware";
      users.users.root.hashedPassword = lib.mkForce null;
      systemd.tmpfiles.rules = [ "d /boot/sensr 0755 root root -" ];
    };

  testScript = ''
    router.wait_for_unit("multi-user.target")

    # Fake generations 1..9 (plain store paths are enough for the cleanup),
    # and a boot slot naming a path that no generation has.
    router.succeed("""
      set -e
      mkdir -p /var/lib/fake-firmware/current /var/lib/fake-firmware/previous
      for i in 1 2 3 4 5 6 7 8 9; do
        d=$(mktemp -d); echo "gen $i $RANDOM" > $d/f
        p=$(nix-store --add "$d")
        echo "$p" > /tmp/gen-$i
        ln -s "$p" /nix/var/nix/profiles/system-$i-link
      done
      ln -sfn system-9-link /nix/var/nix/profiles/system
      # current/ names generation 2's closure; previous/ one with no generation.
      cp /tmp/gen-2 /var/lib/fake-firmware/current/system
      d=$(mktemp -d); echo slot-only > $d/f
      nix-store --add "$d" > /var/lib/fake-firmware/previous/system
    """)

    router.succeed("systemctl start sensr-store-gc.service")

    out = router.succeed("journalctl -u sensr-store-gc.service --no-pager")
    print(out)
    assert "deleting system generations: 5 4 3 1" in out, out

    # 9 (profile), 2 (boot slot), 8 7 6 (newest others) stay; 5 4 3 1 go.
    for i in (2, 6, 7, 8, 9):
        router.succeed(f"test -L /nix/var/nix/profiles/system-{i}-link")
        router.succeed(f"test -e $(cat /tmp/gen-{i})")
    for i in (1, 3, 4, 5):
        router.fail(f"test -e /nix/var/nix/profiles/system-{i}-link")
        router.fail(f"test -e $(cat /tmp/gen-{i})")

    # The slot-only closure has a root and survived; so did the running and
    # booted systems.
    router.succeed("test -e $(cat /var/lib/fake-firmware/previous/system)")
    router.succeed("test -e $(readlink -f /run/booted-system)")
    router.succeed("test -e $(readlink -f /run/current-system)")

    # What the cleanup did is exposed.
    router.succeed("${pkgs.jq}/bin/jq -e '.deleted_generations == [5,4,3,1]' /run/sensr/updates/gc.json")

    # A second run has nothing left to delete.
    router.succeed("systemctl start sensr-store-gc.service")
    out = router.succeed("journalctl -u sensr-store-gc.service --no-pager")
    assert "no system generations to delete" in out, out

    router.succeed("systemctl is-enabled sensr-store-gc.timer || systemctl list-timers | grep sensr-store-gc")
  '';
}
