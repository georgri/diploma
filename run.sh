sudo mount Downloads
sudo rmmod lindacol;
./test.sh && sudo insmod ./lindacol/lindacol.ko && sudo cat /sys/kernel/debug/lindacol/output
