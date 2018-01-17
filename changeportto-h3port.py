from framesnd import sendethframe
#Should change first MAC (source address) with another host MAC address to simulate movement
sendethframe('\x00\x00\x00\x00\x00\x01','\x00\x00\x00\x00\x00\x02','\x88\x8F','xx','h3-eth0')