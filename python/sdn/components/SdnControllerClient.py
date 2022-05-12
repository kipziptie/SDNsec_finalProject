
from influxdb import InfluxDBClient

from components.FirewallEnforcer import FirewallEnforcer

class SdnControllerClient:

    SNORT_VERIFIER_QUERY="select SUM(\"rx-pkts\") from ports WHERE datapath='1' AND time > now() - 20s GROUP BY port;"
    SNORT_VERIFIER_TCP_FLOOD_THRESHOLD=500
    SNORT_VERIFIER_ICMP_FLOOD_THRESHOLD=100

    SELF_VERIFIER_QUERY="select MEAN(\"rx-bytes\") from ports WHERE datapath='1' AND time > now() - 20s GROUP BY port;"
    SELF_VERIFIER_THRESHOLD=10000

    def __init__(self, host='localhost', port='8086', user='root', password='root', dbname='RYU'):
        self.client = InfluxDBClient(host, port, user, password, dbname)
        self.enforcer = FirewallEnforcer()

        internal_port_to_honeypot = 4
        internal_port_to_s2 = 5

        self.alert_cache={}

        # Ignore  any alerts on the internal port id 1
        self.alert_cache[str(internal_port_to_honeypot)] = 1
        self.alert_cache[str(internal_port_to_s2)] = 1

    def monitor_received_bytes_and_react(self):
        result_set = self.client.query(self.SELF_VERIFIER_QUERY)

        for result in list(result_set.keys()):
            port_id = result[1]['port']
            average_rx_bytes = list(result_set.get_points(measurement='ports', tags={"port": port_id}))[0]["mean"]

            if(average_rx_bytes > self.SELF_VERIFIER_THRESHOLD and not port_id in self.alert_cache):
                self.enforcer.enforceRulesBasedOnAttack("average_bytes_exceeded", port_id)
                self.alert_cache[port_id] = 1

    def verify_number_of_packets(self, alert_message):

        result_set = self.client.query(self.SNORT_VERIFIER_QUERY)

        for result in list(result_set.keys()):
            port_id = result[1]['port']
            sum_rx_packets = list(result_set.get_points(measurement='ports', tags={"port": port_id}))[0]["sum"]

            raise_alarm_for_tcp_flood = "SYN" in alert_message and sum_rx_packets > self.SNORT_VERIFIER_TCP_FLOOD_THRESHOLD
            raise_alarm_for_icmp_flood = "ICMP" in alert_message and sum_rx_packets > self.SNORT_VERIFIER_ICMP_FLOOD_THRESHOLD

            if (port_id == 2):
                print(raise_alarm_for_tcp_flood, alert_message, sum_rx_packets)

            if (port_id in self.alert_cache):
                continue

            if (raise_alarm_for_tcp_flood or raise_alarm_for_icmp_flood):
                self.enforcer.enforceRulesBasedOnAttack(alert_message, port_id)
                self.alert_cache[port_id] = 1
                print(alert_message)