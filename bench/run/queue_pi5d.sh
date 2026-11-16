#!/usr/bin/env bash
# Pi 5 NixOS: install (after the OPNsense Pi measurements) and measure.
set -u
cd /mnt/vms/sensr/bench/src/run
W=/mnt/vms/sensr/bench/work
while pgrep -f "bash ./queue_pi5[c]" >/dev/null; do sleep 30; done
python3 -u pi5_nixos.py > $W/pi5_nixos_install.log 2>&1
python3 -u pi5.py measure nixr 3 > $W/pi5_measure_nixr.log 2>&1
echo DONE > $W/queue_pi5d.done
