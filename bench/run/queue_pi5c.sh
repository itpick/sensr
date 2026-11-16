#!/usr/bin/env bash
# Pi 5 (TCG) remaining steps: NixOS aarch64 install + measurements.
set -u
cd /mnt/vms/sensr/bench/src/run
W=/mnt/vms/sensr/bench/work
python3 -u pi5_nixos.py > $W/pi5_nixos_install.log 2>&1
python3 -u pi5.py measure opn 3 > $W/pi5_measure_opn.log 2>&1
python3 -u pi5.py measure nixr 3 > $W/pi5_measure_nixr.log 2>&1
echo DONE > $W/queue_pi5.done
