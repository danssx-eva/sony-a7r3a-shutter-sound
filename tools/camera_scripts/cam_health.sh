#!/bin/busybox sh
echo "UPTIME:"
busybox cat /proc/uptime
echo "LIBOBJ:"
busybox md5sum /usr/lib/libObj.so 2>&1
echo "CAUTIONCFG:"
busybox md5sum /usr/lib/CautionConfig.so 2>&1
echo "SOUND:"
busybox md5sum /usr/share/avsystemsound/Dslr_Emnt_High_Caution.bin 2>&1
echo "TMPLIST:"
busybox md5sum /tmp/beeplist.txt 2>&1
echo "MEMFREE:"
busybox cat /proc/meminfo | busybox grep MemFree
echo "DMESG_ERR:"
busybox dmesg 2>/dev/null | busybox grep -iE 'panic|oops|BUG:|fault|abort|segv|Watchdog' | busybox tail -10
echo "DMESG_TAIL:"
busybox dmesg 2>/dev/null | busybox tail -5
