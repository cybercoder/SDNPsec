from framesnd import sendethframe
# Should replace first argument with valid MAC address of h1 host, and second with valid MAC address of h2 host.
# You can see MAC address of interface with ifconfig command on Linux CLI
sendethframe('\xa2\x62\xcb\xe4\x2b\xe7','\x2a\x05\xfd\xc7\x0f\x1f','\x88\x8F','yy','h1-eth0')