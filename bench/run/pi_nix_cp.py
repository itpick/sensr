"""Pi NixOS: boot until one boot succeeds (initrd /boot race under TCG), then
run the relative control-plane measurements. Boot outcomes are recorded."""
import json, sys, time
sys.path.insert(0, "/mnt/vms/sensr/bench/src/run")
import lab, pi5, controlplane as cp
out = f"{lab.BENCH}/results/pi5.jsonl"
ok = False
for attempt in range(5):
    lab.sh(f"qemu-img create -q -f qcow2 -F qcow2 -b {pi5.IMG['nixr']} {lab.BENCH}/work/pi-nixr.qcow2 && setfacl -m u:qemu-libvirtd:rw {lab.BENCH}/work/pi-nixr.qcow2")
    pi5.define("sensrbench-pi-nixr", f"{lab.BENCH}/work/pi-nixr.qcow2", pi5.PORT["nixr"])
    t0 = time.time()
    lab.virsh("start", "sensrbench-pi-nixr")
    try:
        lab.wait_ssh("router", timeout=420)
        ok = True
    except TimeoutError:
        ok = False
    lab.append_jsonl(out, {"router": "pi-nixr", "part": "boot_attempt", "attempt": attempt, "ok": ok,
                           "t_ssh_s": time.time() - t0 if ok else None, "ts": time.time()})
    if ok:
        break
    lab.virsh("destroy", "sensrbench-pi-nixr")
if ok:
    time.sleep(60)
    cp.OUT = out
    cp.nix_table("pi-nixr", 3)
    cp.proto_full("pi-nixr", 3)
    cp.proto_api("pi-nixr", 3, 20)
lab.virsh("destroy", "sensrbench-pi-nixr", check=False)
