#!/usr/bin/env python3
"""Render a libvirt domain XML for one benchmark VM.

Every VM uses the same machine type, CPU model (host-passthrough), virtio-blk
disk and virtio-net NICs with the vhost backend, so the only variable between
router variants is the guest OS. The serial console is exposed as a raw TCP
socket on 127.0.0.1 so the orchestrator can script and timestamp it.

usage: mkdomain.py NAME DISK VCPUS MEM_MIB CPUSET EMUSET SERIALPORT QUEUES NET:MAC [NET:MAC ...]
  CPUSET  comma list of host CPUs, one per vCPU (vCPU i -> CPUSET[i])
  EMUSET  host CPUs for the emulator + vhost worker threads
"""
import sys

name, disk, vcpus, mem, cpuset, emuset, serial, queues, *nics = sys.argv[1:]
vcpus, mem, queues = int(vcpus), int(mem), int(queues)
cpus = cpuset.split(",")
assert len(cpus) == vcpus, "one host CPU per vCPU"

pins = "\n".join(f"    <vcpupin vcpu='{i}' cpuset='{c}'/>" for i, c in enumerate(cpus))
ifaces = []
for spec in nics:
    net, mac = spec.split(":", 1)
    drv = f"<driver name='vhost' queues='{queues}'/>" if queues > 1 else "<driver name='vhost'/>"
    ifaces.append(f"""    <interface type='network'>
      <source network='{net}'/>
      <mac address='{mac}'/>
      <model type='virtio'/>
      {drv}
    </interface>""")

print(f"""<domain type='kvm'>
  <name>{name}</name>
  <memory unit='MiB'>{mem}</memory>
  <vcpu placement='static'>{vcpus}</vcpu>
  <cputune>
{pins}
    <emulatorpin cpuset='{emuset}'/>
  </cputune>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features><acpi/><apic/></features>
  <cpu mode='host-passthrough' check='none'/>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='none' io='native'/>
      <source file='{disk}'/>
      <target dev='vda' bus='virtio'/>
    </disk>
{chr(10).join(ifaces)}
    <serial type='tcp'>
      <source mode='bind' host='127.0.0.1' service='{serial}'/>
      <protocol type='raw'/>
    </serial>
    <console type='tcp'>
      <source mode='bind' host='127.0.0.1' service='{serial}'/>
      <protocol type='raw'/>
      <target type='serial' port='0'/>
    </console>
    <memballoon model='none'/>
  </devices>
</domain>""")
