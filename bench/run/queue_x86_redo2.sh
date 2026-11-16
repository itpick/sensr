#!/usr/bin/env bash
# Redo OpenBSD footprint with the all-partitions disk sum and raw-stream login timing.
set -u
cd /mnt/vms/sensr/bench/src/run
W=/mnt/vms/sensr/bench/work
while [ ! -f $W/queue_x86_redo.done ]; do sleep 30; done
python3 -u footprint.py obsd --boots 5 --idle-boots 2 --out /mnt/vms/sensr/bench/results/footprint-obsd-redo.jsonl > $W/footprint_obsd_redo.log 2>&1
echo DONE > $W/queue_x86_redo2.done
