sensr first-boot seed folder (@SEED_DIR@)
==========================================

Put files here on any computer before the first boot. sensr reads each one
once, applies it and renames it to <name>.applied so it is not applied again.

  config.json            a full sensr config (a backup export); applied as
                         revision 1
  seed.toml              a small hand-written seed: hostname, admin password
                         hash and SSH keys, which NIC is lan/wan (by MAC, PCI
                         path or first-link-up), WAN type (dhcp, pppoe,
                         static); merged over the defaults
  config.xml             an OPNsense backup; imported, with a report written
                         to import-report.txt next to it
  ifnames                lines of "<mac> <name>" that name NICs before
                         networking starts
  authorized_keys        SSH keys for the admin account (SSH on LAN only)
  reboot-after-minutes   a number N: reboot into the previous generation N
                         minutes after every boot until you delete this file

Binding networks to cards. sensr binds each interface to a card by its MAC
address, never by slot or USB port, so a card that moves keeps its network:

  seed.toml        hostname = "gw"
                   [interfaces]
                   wan = "00:e0:4c:68:00:01"   # MAC, or a kernel name: "end0"
                   lan = "2c:cf:67:00:00:01"
  ifnames          00:e0:4c:68:00:01 ue0       # binds the interface that uses
                   2c:cf:67:00:00:01 igc1      # an imported OPNsense device

After boot, `sensr interfaces list` shows the cards and `sensr interfaces
assign` changes the binding (interactively without arguments).

sensr writes diag-<stage>.txt here (journal, addresses, nft ruleset, kernel
log) so a box that never reaches the network still leaves a post-mortem.

Without any seed: the first NIC becomes lan (192.168.1.1/24, DHCP and DNS on)
and the second becomes wan (DHCP).

Status: sensr is pre-release. Which of these files the running version
already reads is listed on https://itpick.github.io/sensr/.
