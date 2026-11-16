#!/usr/bin/env bash
# OPNsense idle process/RSS numbers (FreeBSD ps -o parsing fix): one idle boot each.
set -u
cd /mnt/vms/sensr/bench/src/run
W=/mnt/vms/sensr/bench/work
while [ ! -f $W/queue_x86_redo5.done ]; do sleep 30; done
for k in opn opnL; do
  python3 -u footprint.py $k --boots 1 --idle-boots 1 --out /mnt/vms/sensr/bench/results/footprint-opn-idle.jsonl >> $W/footprint_opn_idle.log 2>&1
done
echo DONE > $W/queue_x86_redo6.done
