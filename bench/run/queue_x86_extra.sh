#!/usr/bin/env bash
# Follow-ups after queue_x86.sh: OpenBSD q=2 rerun (first attempt lost its ssh
# control channel), OPNsense checksum+TSO-only variant, then the Pi 5 track.
set -u
cd /mnt/vms/sensr/bench/src/run
W=/mnt/vms/sensr/bench/work
while [ ! -f $W/queue_x86.done ]; do sleep 30; done
python3 -u run_x86.py --stages dataplane --queues 2 --labels obsd:as-shipped > $W/run_x86_obsd_q2.log 2>&1
python3 -u run_x86.py --stages dataplane --queues 1 --labels opn:offload-boot-nolro > $W/run_x86_nolro.log 2>&1
echo DONE > $W/queue_x86_extra.done
