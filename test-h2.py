from framesnd import sendethframe
# Should replace first argument with valid MAC address of h1 host, and second with valid MAC address of h2 host.
# You can see MAC address of interface with ifconfig command on Linux CLI
sendethframe('\x00\x00\x00\x00\x00\x02','\x00\x00\x00\x00\x00\x01','\x88\x8F','xx','h2-eth0')
