from socket import *

def sendethframe(src, dst, eth_type, payload, interface = "eth0"):
  """Send RAW Ethernet Frame."""

  assert(len(src) == len(dst) == 6) # 48-bit ethernet addresses
  assert(len(eth_type) == 2) # 16-bit ethernet type

  s = socket(AF_PACKET, SOCK_RAW)

  s.bind((interface, 0))
  return s.send(dst + src + eth_type + payload)
