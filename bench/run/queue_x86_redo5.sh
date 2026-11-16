#!/usr/bin/env bash
# Control-plane reruns: OpenBSD (first apply run had a shell-expansion bug; BSD
# timings now sub-ms), OPNsense raw pfctl table timings (sub-ms), and the
# streaming-renderer prototype (static musl build pushed into the NixOS VM).
set -u
cd /mnt/vms/sensr/bench/src/run
W=/mnt/vms/sensr/bench/work
while [ ! -f $W/queue_x86_redo4.done ]; do sleep 30; done
python3 - <<'PY'
import json
p = "/mnt/vms/sensr/bench/results/controlplane.jsonl"
rows = [json.loads(l) for l in open(p)]
bad = lambda r: r["router"] in ("obsd", "obsdL") or (r["router"] == "opn" and r["part"] == "table_raw")
open("/mnt/vms/sensr/bench/results/controlplane-superseded.jsonl", "a").write("".join(json.dumps(r) + "\n" for r in rows if bad(r)))
open(p, "w").write("".join(json.dumps(r) + "\n" for r in rows if not bad(r)))
PY
python3 - <<'PY'
import run_x86, lab
run_x86.boot("obsd", 1)
PY
python3 -u controlplane.py obsd --parts apply,table --reps 5 > $W/control_obsd_redo.log 2>&1
python3 - <<'PY'
import run_x86
run_x86.setup_obsd_large()
PY
python3 -u controlplane.py obsdL --parts apply --reps 5 >> $W/control_obsd_redo.log 2>&1
python3 - <<'PY'
import run_x86
run_x86.boot("opn", 1)
PY
python3 -u controlplane.py opn --parts tableraw --reps 5 > $W/control_opn_raw.log 2>&1
python3 - <<'PY'
import run_x86, lab
run_x86.boot("nixr", 1)
lab.sh(f"scp -F {lab.SSHCFG} -q {lab.BENCH}/work/sensr-proto-x86_64-stream router:/root/sensr-proto-stream")
PY
PROTO_BIN=/root/sensr-proto-stream python3 -u controlplane.py nixr --parts table,proto,apply --reps 5 > $W/control_nixr_stream.log 2>&1
python3 -c "import lab; lab.stop_routers()"
echo DONE > $W/queue_x86_redo5.done
