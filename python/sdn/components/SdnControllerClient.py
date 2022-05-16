
from influxdb import InfluxDBClient
import requests

class SdnControllerClient():

    SNORT_VERIFIER_QUERY="select SUM(\"rx-pkts\") from ports WHERE datapath='1' AND time > now() - 1m GROUP BY port;"
    SNORT_VERIFIER_TCP_FLOOD_THRESHOLD=500
    SNORT_VERIFIER_ICMP_FLOOD_THRESHOLD=100

    SELF_VERIFIER_QUERY="select MEAN(\"rx-bytes\") from ports WHERE datapath='1' AND time > now() - 10s GROUP BY port;"
    SELF_VERIFIER_THRESHOLD=100000000

    INTERNAL_PORT_TO_S2 = 5
    INTERNAL_PORT_TO_HONEYPOT = 4

    def __init__(self, datapath, host='localhost', port='8086', user='root', password='root', dbname='RYU'):
        self.client = InfluxDBClient(host, port, user, password, dbname)

        self.alert_cache={}
        self.datapath=datapath

        # Ignore  any alerts on the internal port id 1
        self.alert_cache[str(self.INTERNAL_PORT_TO_HONEYPOT)] = 1
        self.alert_cache[str(self.INTERNAL_PORT_TO_S2)] = 1

    def monitor_received_bytes_and_react(self):
        result_set = self.client.query(self.SELF_VERIFIER_QUERY)

        for result in list(result_set.keys()):
            port_id = result[1]['port']
            average_rx_bytes = list(result_set.get_points(measurement='ports', tags={"port": port_id}))[0]["mean"]

            if(average_rx_bytes > self.SELF_VERIFIER_THRESHOLD and not port_id in self.alert_cache):
                print("Found alert")
                self._enforceRulesBasedOnAttack("average_bytes_exceeded", port_id)
                self.alert_cache[port_id] = 1

    def verify_number_of_packets(self, alert_message):

        result_set = self.client.query(self.SNORT_VERIFIER_QUERY)

        for result in list(result_set.keys()):

            port_id = result[1]['port']
            sum_rx_packets = list(result_set.get_points(measurement='ports', tags={"port": port_id}))[0]["sum"]

            raise_alarm_for_tcp_flood = "SYN" in alert_message and int(sum_rx_packets) > self.SNORT_VERIFIER_TCP_FLOOD_THRESHOLD
            raise_alarm_for_icmp_flood = "ICMP" in alert_message and int(sum_rx_packets) > self.SNORT_VERIFIER_ICMP_FLOOD_THRESHOLD

            if (port_id == "1" or port_id == "2"):
                print(raise_alarm_for_icmp_flood, raise_alarm_for_tcp_flood, alert_message, sum_rx_packets)

            if (port_id in self.alert_cache):
                continue

            if (raise_alarm_for_tcp_flood or raise_alarm_for_icmp_flood):
                self._enforceRulesBasedOnAttack(alert_message, port_id)
                self.alert_cache[port_id] = 1
                print(alert_message)

    def _block_traffic(self, port_id):
        data='{"in_port": "' + str(port_id) + '", "nw_proto": "ICMP", "dl_type": "IPv4", "actions": "DENY", "priority": 100}'
        result = requests.post('http://localhost:8080/firewall/rules/0000000000000001', data=data)
        if (result.status_code != 200):
            raise Exception("Failed to perform request: "+str(result.status_code))

        print(result.text)

        print("[Firewall Enforcer]: I will block the traffic for port", port_id)


    def _redirect_traffic_to_honeypot(self, port_id):
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser

        actions = [parser.OFPActionOutput(self.INTERNAL_PORT_TO_HONEYPOT)]

        match = parser.OFPMatch(in_port=int(port_id))
        self.add_flow(self.datapath, 90, match, actions)

        print("[Firewall Enforcer]: I will redirect the traffic for port", port_id)

    def _enforceRulesBasedOnAttack(self, attack_type, port_id):
        if ( "SYN" in attack_type ):
            self._redirect_traffic_to_honeypot(port_id)
        else:
            self._block_traffic(port_id)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)