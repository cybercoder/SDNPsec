from framesnd import sendethframe
#Should change first MAC (source address) with another host spoofed MAC address
sendethframe('\x00\x00\x00\x00\x00\x01','\x00\x00\x00\x00\x00\x02','\x88\x8F','eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtYWMiOiIwMDAwMDAwMDAwMDEifQ.bT_cLEJWSU9f_VdDQ74aGvQQPwoPmnVZ0DzZ5','h3-eth0')