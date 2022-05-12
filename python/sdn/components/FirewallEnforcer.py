class FirewallEnforcer:

    def __init__(self):
        self.test = "null"

    def _block_traffic(self, port_id):
        print("[Firewall Enforcer]: I will block the traffic for port", port_id)

    def _redirect_traffic_to_honeypot(self, port_id):
        print("[Firewall Enforcer]: I will redirect the traffic for port", port_id)

    def enforceRulesBasedOnAttack(self, attack_type, port_id):
        if ( "TCP" in attack_type ):
            self._redirect_traffic_to_honeypot(port_id)
        else:
            self._block_traffic(port_id)