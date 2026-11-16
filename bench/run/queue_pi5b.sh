#!/usr/bin/env bash
# Pi 5 (emulated, TCG) track.
set -u
cd /mnt/vms/sensr/bench/src/run
W=/mnt/vms/sensr/bench/work
rm -f $W/queue_pi5.done
python3 -c "import lab; lab.stop_routers()"
python3 -u pi5.py prep-opn > $W/pi5_prep_opn.log 2>&1
python3 -u pi5_nixos.py > $W/pi5_nixos_install.log 2>&1
python3 -u pi5.py measure opn 3 > $W/pi5_measure_opn.log 2>&1
python3 -u pi5.py measure opnL 1 > $W/pi5_measure_opnL.log 2>&1
python3 -u pi5.py measure nixr 3 > $W/pi5_measure_nixr.log 2>&1
echo DONE > $W/queue_pi5.done
