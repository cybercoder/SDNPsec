from framesnd import sendethframe
#Should change first MAC (source address) with another host MAC address to simulate movement
sendethframe('\x2a\x05\xfd\xc7\x0f\x1f','\xa2\x62\xcb\xe4\x2b\xe7','\x88\x8F','xx','h3-eth0')