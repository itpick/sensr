#!/usr/bin/env bash
# OPNsense control plane: the 100k alias step via the API, plus api/gui (first run crashed before them).
set -u
cd /mnt/vms/sensr/bench/src/run
W=/mnt/vms/sensr/bench/work
while [ ! -f $W/queue_x86_redo3.done ]; do sleep 30; done
python3 - <<'PY'
import run_x86
run_x86.boot("opn", 1)
PY
TABLE_SIZES=100k python3 -u controlplane.py opn --parts tablemgmt,api,gui --reps 5 > $W/control_opn_redo.log 2>&1
echo DONE > $W/queue_x86_redo4.done
