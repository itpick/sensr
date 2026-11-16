# Boot the real images.qcow artifact (not the test VM nixosTest builds): UEFI
# firmware, systemd-boot with boot counting, the ESP mounted nofail. Passes
# when the selftest prints PASS on the serial console, and records how long
# that took in $out/boot-seconds. Run a few boots: the benchmark's NixOS
# image failed 3 of 5 (docs/research/07).
{
  pkgs,
  image,
  boots ? 3,
}:
pkgs.runCommand "sensr-qcow-boot"
  {
    nativeBuildInputs = with pkgs; [
      qemu_test
      coreutils
      gnugrep
    ];
    requiredSystemFeatures = [ "kvm" ];
  }
  ''
    mkdir -p $out
    fw=${pkgs.OVMF.fd}/FV
    img=$(echo ${image}/*.qcow2)
    for n in $(seq 1 ${toString boots}); do
      # A fresh copy each time: the first boot of an image is the one users get.
      cp --no-preserve=mode "$img" disk.qcow2
      cp --no-preserve=mode $fw/OVMF_VARS.fd vars.fd
      log=$out/boot-$n.log
      start=$(date +%s.%N)
      qemu-system-x86_64 -machine q35,accel=kvm -cpu host -smp 2 -m 1024 \
        -drive if=pflash,format=raw,readonly=on,file=$fw/OVMF_CODE.fd \
        -drive if=pflash,format=raw,file=vars.fd \
        -drive file=disk.qcow2,if=virtio \
        -nic none -display none -serial file:$log -no-reboot &
      pid=$!
      ok=
      for _ in $(seq 1 1200); do
        if grep -q 'sensr-selftest: PASS' $log 2>/dev/null; then ok=1; break; fi
        if grep -q 'sensr-selftest: FAIL' $log 2>/dev/null; then break; fi
        kill -0 $pid 2>/dev/null || break
        sleep 0.1
      done
      end=$(date +%s.%N)
      kill $pid 2>/dev/null || true
      wait $pid 2>/dev/null || true
      if [ -z "$ok" ]; then
        echo "boot $n: no selftest PASS on the serial console"; tail -n 60 $log; exit 1
      fi
      secs=$(echo "$start $end" | awk '{printf "%.1f", $2 - $1}')
      echo "boot $n: selftest PASS after $secs s"
      echo "$secs" >> $out/boot-seconds
    done
    du -b "$img" | cut -f1 > $out/image-bytes
  ''
