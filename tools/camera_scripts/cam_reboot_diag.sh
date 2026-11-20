#!/bin/busybox sh
echo "UPTIME:"
busybox cat /proc/uptime
echo "LIBOBJ:"
busybox md5sum /usr/lib/libObj.so 2>&1
echo "DMESG_LAST30:"
busybox dmesg 2>/dev/null | busybox tail -30
echo "DMESG_KEYWORDS:"
busybox dmesg 2>/dev/null | busybox grep -iE 'panic|oops|BUG|fault|abort|watchdog|reset|reboot|power|kill' | busybox tail -18
