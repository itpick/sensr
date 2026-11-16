#!/usr/bin/env bash
# Remaining x86 stages in order (each waits for the previous). Logs in $BENCH/work.
set -u
cd /mnt/vms/sensr/bench/src/run
W=/mnt/vms/sensr/bench/work
while pgrep -f "run_x86.py --stages dataplane --queues 2" >/dev/null; do sleep 20; done
python3 -u run_x86.py --stages dataplane --labels opn:offload-boot > $W/run_x86_offload.log 2>&1
python3 -u run_x86.py --stages footprint > $W/run_x86_footprint.log 2>&1
python3 -u run_x86.py --stages control > $W/run_x86_control.log 2>&1
echo DONE > $W/queue_x86.done
