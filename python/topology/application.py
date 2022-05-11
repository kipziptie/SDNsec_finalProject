from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController

from MyTopo import MyTopo


def disableIPv6(net, topo):
    for host in topo.hosts():
        net.get(host).cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
        net.get(host).cmd('sysctl -w net.ipv6.conf.lo.disable_ipv6=1')
        net.get(host).cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')

    for switch in topo.switches():
        net.get(switch).cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
        net.get(switch).cmd('sysctl -w net.ipv6.conf.lo.disable_ipv6=1')
        net.get(switch).cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')


topo = MyTopo()

net = Mininet(topo=topo, controller=None, autoStaticArp=True)

net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6633)

net.start()

disableIPv6(net, topo)
CLI(net)
net.stop()