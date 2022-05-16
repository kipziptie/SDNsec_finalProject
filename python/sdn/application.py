# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function

import array
import requests

from requests.exceptions import ConnectionError

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp

from ryu.lib import snortlib
from ryu.lib import hub

from components.SdnControllerClient import SdnControllerClient

class IDS_Application(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(IDS_Application, self).__init__(*args, **kwargs)
        self.snort = kwargs['snortlib']
        self.snort_port = 6
        self.mac_to_port = {}

        socket_config = {'unixsock': True}

        self.snort.set_config(socket_config)
        self.snort.start_socket_server()
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handler_datapath(self, ev):
        datapath = ev.msg.datapath
        
        if ( datapath.id == 1 ):
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                            ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 0, match, actions)

            self._initialise_firewall_rules()

            self.client = SdnControllerClient(datapath)
            self.influx_verifier = hub.spawn(self._influx_verify)

    def _initialise_firewall_rules(self):

        host_is_up = False

        while not host_is_up:
            try:
                v = requests.get('http://localhost:8080/firewall/module/status')
                host_is_up = True    
            except ConnectionError:
                print("Firewall Rest API is down. Sleeping and retrying")
                hub.sleep(10)        

        self._perform_request('PUT', 'http://localhost:8080/firewall/module/enable/0000000000000001')
        self._perform_request('PUT', 'http://localhost:8080/firewall/module/enable/0000000000000002')

        self._perform_request('POST', 'http://localhost:8080/firewall/rules/0000000000000001', '{"nw_src": "10.0.0.5/32"}')
        self._perform_request('POST', 'http://localhost:8080/firewall/rules/0000000000000001', '{"nw_dst": "10.0.0.5/32"}')

        self._perform_request('POST', 'http://localhost:8080/firewall/rules/0000000000000002', '{"nw_src": "10.0.0.5/32"}')
        self._perform_request('POST', 'http://localhost:8080/firewall/rules/0000000000000002', '{"nw_dst": "10.0.0.5/32"}')

        

    def _perform_request(self, type, url, data=None):

        if (type == "GET"):
            result = requests.get(url)
        elif (type == "PUT"):
            result = requests.put(url)
        elif (type == "POST"):
            result = requests.post(url, data=data)
        else:
            result = requests.delete(url)

        if (result.status_code != 200):
            raise Exception("Failed to perform request: "+result.status_code)

        return result.text



    def _influx_verify(self):
        self.logger.info("Start monitoring")
        while True:
            self.client.monitor_received_bytes_and_react()
            hub.sleep(10)

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        msg = ev.msg
        #print('alertmsg: %s' % msg.alertmsg[0].decode())
        self.client.verify_number_of_packets(msg.alertmsg[0].decode())
        
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)