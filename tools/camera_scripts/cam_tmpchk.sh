#!/bin/busybox sh
echo "MOUNTS:"
busybox cat /proc/mounts | busybox grep -E ' /tmp | /dev/shm | /var '
echo "TMPLS:"
busybox ls -la /tmp/ 2>&1 | busybox head -20
echo "WRITETEST:"
busybox echo TESTDATA > /tmp/_w.txt 2>&1
busybox echo "wrc=rc"
busybox cat /tmp/_w.txt 2>&1
busybox rm -f /tmp/_w.txt
echo "BEEPLIST_TMP:"
busybox ls -l /tmp/beeplist.txt 2>&1
echo "BEEPLIST_USR:"
busybox ls -l /usr/share/avsystemsound/beeplist.txt 2>&1
echo "DF:"
busybox df 2>&1 | busybox head -10
