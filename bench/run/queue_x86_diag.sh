#!/usr/bin/env bash
set -u
cd /mnt/vms/sensr/bench/src/run
W=/mnt/vms/sensr/bench/work
while [ ! -f $W/queue_x86_redo6.done ]; do sleep 30; done
python3 -u diag.py > $W/diag.log 2>&1
echo DONE > $W/queue_x86_diag.done
