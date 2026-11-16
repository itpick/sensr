#!/usr/bin/env bash
# After the VyOS large-config reload: redo every vyosL measurement, run the
# connection-latency diagnostic, then the Pi 5 (TCG) track.
set -u
cd /mnt/vms/sensr/bench/src/run
W=/mnt/vms/sensr/bench/work
R=/mnt/vms/sensr/bench/results
while pgrep -f "vyos_large_fi[x]" >/dev/null; do sleep 30; done
python3 - <<'PY'
import json
R = "/mnt/vms/sensr/bench/results"
for f, keep in (("dataplane.jsonl", lambda r: r["router"] != "vyosL"),
                ("footprint.jsonl", lambda r: r["router"] != "vyosL"),
                ("controlplane.jsonl", lambda r: not (r["router"] == "vyosL" and r["part"] in ("apply", "api", "apply_api")))):
    rows = [json.loads(l) for l in open(f"{R}/{f}")]
    open(f"{R}/superseded-{f}", "a").write("".join(json.dumps(r) + "\n" for r in rows if not keep(r)))
    open(f"{R}/{f}", "w").write("".join(json.dumps(r) + "\n" for r in rows if keep(r)))
PY
python3 -u run_x86.py --stages dataplane --queues 1 --labels vyosL:large > $W/run_vyosL_dataplane.log 2>&1
python3 -u footprint.py vyosL --boots 3 --idle-boots 1 > $W/footprint_vyosL.log 2>&1
python3 - <<'PY'
import run_x86
run_x86.boot("vyosL", 1)
PY
python3 -u controlplane.py vyosL --parts apply,api --reps 5 > $W/control_vyosL.log 2>&1
python3 -u diag.py connlat > $W/diag_connlat.log 2>&1
python3 - <<'PY'
import diag, lab
diag.nft_diag("vyosL", "vyos", "sudo nft list chain ip vyos_filter VYOS_FORWARD_filter | head -60; sudo nft list chain ip vyos_filter VYOS_FORWARD_filter | wc -l")
lab.stop_routers()
PY
echo DONE > $W/queue_final_x86.done
rm -f $W/queue_pi5.done
python3 -u pi5.py prep-opn > $W/pi5_prep_opn.log 2>&1
python3 -u pi5_nixos.py > $W/pi5_nixos_install.log 2>&1
python3 -u pi5.py measure opn 3 > $W/pi5_measure_opn.log 2>&1
python3 -u pi5.py measure opnL 1 > $W/pi5_measure_opnL.log 2>&1
python3 -u pi5.py measure nixr 3 > $W/pi5_measure_nixr.log 2>&1
echo DONE > $W/queue_pi5.done
