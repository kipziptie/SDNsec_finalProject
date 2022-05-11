from mininet.topo import Topo
class MyTopo(Topo):
	def __init__(self, **opts):
		# Initialize topology
		Topo.__init__(self, **opts)
		switches=[]
		hosts=[]
		
		# Adding hosts
		attacker1 = self.addHost('attacker1')
		attacker2 = self.addHost('attacker2')
		host = self.addHost('host')
		
		# Adding ovsk switches
		s1 = self.addSwitch('s1', protocols='OpenFlow13')
		s2 = self.addSwitch('s2', protocols='OpenFlow13')

		# Adding servers
		honeypot = self.addHost('honeypot')
		server = self.addHost('server')
		
		# Add (bidirectional) links
		self.addLink(attacker1, s1)
		self.addLink(attacker2, s1)
		self.addLink(host, s1)
		self.addLink(s1, honeypot)
		self.addLink(s1, s2)
		self.addLink(s2, server)

		switches.append(s1)
		switches.append(s2)

		hosts.append(attacker1)
		hosts.append(attacker2)
		hosts.append(host)
		hosts.append(honeypot)
		hosts.append(server)
		
		
# Adding the 'topos' dict with a key/value pair to
# generate our newly defined topology enables one
# to pass in '--topo=mytopo' from the command line.
topos = {'mytopo': (lambda: MyTopo())}
