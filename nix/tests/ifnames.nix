# Interfaces are bound to cards by MAC, not by slot (docs/PLAN.md §6 L3).
# VyOS names USB NICs by port, which swapped networks on a real cutover.
# Here three cards (two PCI, one USB) are assigned from the seed folder's
# seed.toml; between boots the two PCI cards swap slots and the USB card
# moves to another port. Every role must stay on its card: same name, same
# MAC, LAN address on the LAN card. A runtime reassignment then swaps WAN
# and LAN without a reboot. The seed's authorized_keys reaches root's sshd
# key file.
{
  pkgs,
  sensrModules,
}:
let
  wanMac = "52:54:00:aa:00:01";
  lanMac = "52:54:00:aa:00:02";
  usbMac = "52:54:00:aa:00:03";
  key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC8u6EM1pQBx4cCeioZw0En7NYq7SYguxI03/I6QYJwx admin@laptop";
in
pkgs.testers.runNixOSTest {
  name = "sensr-ifnames";
  nodes.machine =
    { ... }:
    {
      imports = sensrModules ++ [ ../images/common.nix ];
      virtualisation.memorySize = 1024;
      # Only the cards the test script adds (QEMU_OPTS); no test VLANs.
      virtualisation.vlans = [ ];
      users.users.root.hashedPassword = pkgs.lib.mkForce null;
      services.sensr.applier = "slice";
      services.sensr.seedDir = "/boot/sensr";
      # the seed folder as a freshly written card would have it
      systemd.tmpfiles.rules = [
        "d /boot/sensr 0755 root root -"
        "C /boot/sensr/seed.toml - - - - /etc/sensr-test/seed.toml"
        "C /boot/sensr/authorized_keys - - - - /etc/sensr-test/authorized_keys"
      ];
      environment.etc."sensr-test/seed.toml".text = ''
        hostname = "pinned"
        [interfaces]
        wan = "${wanMac}"
        lan = "${lanMac}"
        opt1 = "${usbMac}"
      '';
      environment.etc."sensr-test/authorized_keys".text = "${key}\n";
      environment.systemPackages = [ pkgs.jq ];
      boot.kernelModules = [
        "usbnet"
        "cdc_ether"
      ];
    };

  testScript = ''
    import json
    import os

    WAN, LAN, USB = "${wanMac}", "${lanMac}", "${usbMac}"

    def cards(pci_wan, pci_lan, usb_port):
        return " ".join([
            f"-netdev user,id=nwan -device virtio-net-pci,netdev=nwan,mac={WAN},addr={pci_wan}",
            f"-netdev user,id=nlan -device virtio-net-pci,netdev=nlan,mac={LAN},addr={pci_lan}",
            "-device qemu-xhci,id=xhci",
            f"-netdev user,id=nusb -device usb-net,netdev=nusb,mac={USB},bus=xhci.0,port={usb_port}",
        ])

    def mac(dev):
        return machine.succeed(f"cat /sys/class/net/{dev}/address").strip()

    def bus_paths():
        nics = json.loads(machine.succeed("sensr interfaces list --json"))
        print(json.dumps(nics, indent=1))
        return {n["assigned"]: n["bus_path"] for n in nics if n["assigned"]}

    def roles_on_their_cards(wan=WAN, lan=LAN):
        machine.wait_until_succeeds("test -e /sys/class/net/wan && test -e /sys/class/net/lan", timeout=60)
        print(machine.succeed("ip -br link; ip -br addr"))
        assert mac("wan") == wan, mac("wan")
        assert mac("lan") == lan, mac("lan")
        assert mac("opt1") == USB, mac("opt1")
        machine.wait_until_succeeds("ip -4 addr show dev lan | grep -q 'inet 192.168.1.1/24'", timeout=60)

    with subtest("first boot: seed.toml binds roles to MACs"):
        os.environ["QEMU_OPTS"] = cards("0x10", "0x11", 1)
        machine.start()
        machine.wait_for_unit("sensr-agent.service")
        roles_on_their_cards()
        machine.succeed("sensr config get system.hostname | grep -qx pinned")
        for dev in ["wan", "lan", "opt1"]:
            machine.succeed(f"grep -q 'Name={dev}' /var/lib/sensr/links/10-sensr-{dev}.link")
        before = bus_paths()

    with subtest("seed authorized_keys reach root's sshd key file"):
        machine.succeed("test -e /boot/sensr/authorized_keys.applied && ! test -e /boot/sensr/authorized_keys")
        machine.succeed("stat -c '%a' /run/sensr/ssh/authorized_keys/root | grep -qx 644")
        machine.succeed("grep -qF 'admin@laptop' /run/sensr/ssh/authorized_keys/root")

    with subtest("cards change slot and port; roles stay on their MACs"):
        machine.shutdown()
        os.environ["QEMU_OPTS"] = cards("0x11", "0x10", 2)
        machine.start()
        machine.wait_for_unit("sensr-agent.service")
        machine.succeed("systemctl is-active sensr-ifnames.service")
        roles_on_their_cards()
        after = bus_paths()
        assert after["wan"] != before["wan"] and after["lan"] != before["lan"], (before, after)
        assert after["opt1"] != before["opt1"], (before, after)
        # still the factory addressing on the LAN card, so DHCP keeps serving it
        machine.succeed("sensr config get interfaces.lan.match_mac | grep -qx ${lanMac}")

    with subtest("runtime reassignment swaps WAN and LAN without a reboot"):
        machine.succeed(f"sensr interfaces assign wan={LAN} lan={WAN} --commit")
        roles_on_their_cards(wan=LAN, lan=WAN)
        machine.succeed(f"grep -q 'PermanentMACAddress={WAN}' /var/lib/sensr/links/10-sensr-lan.link")

    with subtest("nothing failed"):
        machine.succeed("test -z \"$(systemctl list-units --failed --no-legend)\" || (systemctl list-units --failed; false)")
  '';
}
