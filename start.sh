#!/bin/sh
cd /workspace
hciconfig hci0 up
start-stop-daemon -S -q -m -b -p /var/run/bluetoothd.pid -x /usr/libexec/bluetooth/bluetoothd -- -C
hciconfig
while :
do
    python3 ./adv_sign.py
done
