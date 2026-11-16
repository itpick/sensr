# The slice's addressing plan, shared by the router configs, the client VMs
# and the test script.
#
#   vlan 1  WAN       router igc0 (DHCP) <-> upstream 11.0.0.1 (DHCP server)
#   vlan 2  LAN       router igc1 192.168.1.1/24, VLAN 20 (IoT) and 30 (Guest)
#                     on the same wire; clients lan, nas, iot
#   vlan 3  internet  upstream 11.0.1.1 <-> internet 11.0.1.10
#
# The "internet" is 11.0.0.0/16: it only has to be outside the private and
# bogon ranges the imported WAN rules block (blockpriv, blockbogons; the
# documentation ranges are bogons), so that new connections from it reach
# the router's WAN rules at all. Nothing leaves the test's virtual networks.
{
  wan = {
    vlan = 1;
    upstream = "11.0.0.1";
    prefix = 24;
    pool = {
      first = "11.0.0.100";
      last = "11.0.0.200";
    };
  };
  internet = {
    vlan = 3;
    upstream = "11.0.1.1";
    host = "11.0.1.10";
    prefix = 24;
  };
  lan = {
    vlan = 2;
    router = "192.168.1.1";
    # Kea subnet "LAN clients" in home-router.xml.
    poolFirst = 100;
    poolLast = 199;
  };
  # Kea reservations in home-router.xml.
  nas = {
    mac = "02:00:5e:10:00:0a";
    ip = "192.168.1.10";
  };
  iot = {
    vlanId = 20;
    router = "192.168.20.1";
    # reservation "thermostat"
    mac = "02:00:5e:20:00:0a";
    ip = "192.168.20.10";
  };

  # WireGuard: the router's key is the fixture's server privkey (32 bytes,
  # so a valid key; its public key below is derived with `wg pubkey`). The
  # fixture's peer public keys are placeholders nobody holds the private key
  # for, so the slice replaces peer "phone"'s key with this test-only pair.
  # TEST KEYS: never use them anywhere else.
  wg = {
    port = 51820;
    serverPrivate = "U1lOVEhFVElDLVdHLXNydi1wcml2LU5PVC1BLVJFQUw=";
    serverPublic = "K+XZFKSmtdeV2JOzksP4XZuSPtOecZfORGSDrgWZ8mE=";
    phonePrivate = "IDizVRIFxZv8+zLdmMir4DkKWuaG17CL6cQJRQGr2Vs=";
    phonePublic = "fRIi+M+cbRFQ1h80SGskSdjvmNqm7DXG/5KmeouX8yo=";
    # the fixture's psk for phone (32 bytes)
    phonePsk = "U1lOVEhFVElDLVdHLXBob25lLXBzay1OT1QtQS1SRUE=";
    # peer "phone" in home-router.xml
    phoneUuid = "6df6330a-0cd5-4702-8527-04771aa9d231";
    serverAddress = "10.10.10.1";
    phoneAddress = "10.10.10.2";
  };
}
