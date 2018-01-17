from framesnd import sendethframe
#Should change first MAC (source address) with another host spoofed MAC address
sendethframe('\x00\x00\x00\x00\x00\x01','\x00\x00\x00\x00\x00\x02','\x88\x8F','123idontknowtoken','h3-eth0')