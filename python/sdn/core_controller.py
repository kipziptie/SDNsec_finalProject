from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import route
from ryu.app.wsgi import WSGIApplication

from ryu.lib import hub

import socket
import datetime
import json

UDP_IP = "127.0.0.1"
UDP_PORT = 8094

simple_switch_instance_name = 'simple_switch_api_app'
url = '/simpleswitch/mactable'
firewall_switch_id = 1

class CoreController(simple_switch_13.SimpleSwitch13):

    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(CoreController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        wsgi = kwargs['wsgi']
        wsgi.register(SimpleSwitchController,
                      {simple_switch_instance_name: self})


    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        FLOW_MSG = "flows,datapath=%x in-port=%x,eth-dst=\"%s\",out-port=%x,packets=%d,bytes=%d %d"
        body = ev.msg.body
        # self.logger.info('stats received: %016x', ev.msg.datapath.id)

        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
            msg = FLOW_MSG % (ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count,
                             timestamp)
            # self.logger.info(msg)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(msg.encode(), (UDP_IP, UDP_PORT))

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        PORT_MSG = "ports,datapath=%x,port=%x rx-pkts=%d,rx-bytes=%d,rx-error=%d,tx-pkts=%d,tx-bytes=%d,tx-error=%d %d"
        body = ev.msg.body
        # self.logger.info('stats received: %016x', ev.msg.datapath.id)

        for stat in sorted(body, key=attrgetter('port_no')):
            timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
            msg = PORT_MSG % (ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors,
                             timestamp)
            # self.logger.info(msg)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(msg.encode(), (UDP_IP, UDP_PORT))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        super(CoreController, self).switch_features_handler(ev)
        datapath = ev.msg.datapath
        if (datapath.id == firewall_switch_id):
            self.mac_to_port = {}

    def set_mac_to_port(self, entry):
        datapath = self.switches.get(firewall_switch_id)

        entry_port = entry['port']
        entry_mac = entry['mac']

        if datapath is not None:
            parser = datapath.ofproto_parser
            if entry_port not in mac_table.values():

                for mac, port in mac_table.items():

                    # from known device to new device
                    actions = [parser.OFPActionOutput(entry_port)]
                    match = parser.OFPMatch(in_port=port, eth_dst=entry_mac)
                    self.add_flow(datapath, 100, match, actions)

                    # from new device to known device
                    actions = [parser.OFPActionOutput(port)]
                    match = parser.OFPMatch(in_port=entry_port, eth_dst=mac)
                    self.add_flow(datapath, 100, match, actions)

                mac_table.update({entry_mac: entry_port})
        return mac_table

class SimpleSwitchController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(SimpleSwitchController, self).__init__(req, link, data, **config)
        self.simple_switch_app = data[simple_switch_instance_name]

    @route('simpleswitch', '/simpleswitch/mactable', methods=['GET'])
    def list_mac_table(self, req, **kwargs):

        simple_switch = self.simple_switch_app

        mac_table = simple_switch.mac_to_port
        body = json.dumps(mac_table)
        return Response(content_type='application/json', text=body)

    @route('simpleswitch', '/simpleswitch/mactable', methods=['PUT'])
    def put_mac_table(self, req, **kwargs):

        simple_switch = self.simple_switch_app

        try:
            new_entry = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        try:
            mac_table = simple_switch.set_mac_to_port(new_entry)
            body = json.dumps(mac_table)
            return Response(content_type='application/json', text=body)
        except Exception as e:
            return Response(status=500)