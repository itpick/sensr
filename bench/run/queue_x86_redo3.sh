#!/usr/bin/env bash
# Redo NixOS boot timings (the API probe had a scoping bug in the first pass).
set -u
cd /mnt/vms/sensr/bench/src/run
W=/mnt/vms/sensr/bench/work
while [ ! -f $W/queue_x86_redo2.done ]; do sleep 30; done
python3 -u footprint.py nixr --boots 5 --idle-boots 1 --out /mnt/vms/sensr/bench/results/footprint-nixr-redo.jsonl > $W/footprint_nixr_redo.log 2>&1
echo DONE > $W/queue_x86_redo3.done
