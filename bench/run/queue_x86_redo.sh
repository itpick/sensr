#!/usr/bin/env bash
# Redo OPNsense footprint (first attempt hit a ps-parsing bug), after the other queues.
set -u
cd /mnt/vms/sensr/bench/src/run
W=/mnt/vms/sensr/bench/work
while [ ! -f $W/queue_x86_extra.done ]; do sleep 30; done
python3 -u run_x86.py --stages footprint --only opn,opnL > $W/run_x86_footprint_opn.log 2>&1
echo DONE > $W/queue_x86_redo.done
