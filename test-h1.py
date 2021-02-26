from framesnd import sendethframe
# Should replace first argument with valid MAC address of h1 host, and second with valid MAC address of h2 host.
# You can see MAC address of interface with ifconfig command on Linux CLI
sendethframe('\x00\x00\x00\x00\x00\x01','\x00\x00\x00\x00\x00\x02','\x88\x8F','eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtYWMiOiIwMDAwMDAwMDAwMDEifQ.bT_cLEJmujVAXlLU9f_VdDQ74aGvQQPwoPmnVZ0DzZ4','h1-eth0')