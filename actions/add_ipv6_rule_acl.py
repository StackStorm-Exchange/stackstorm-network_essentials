import sys
from ne_base import NosDeviceAction
from ne_base import log_exceptions


class Add_Ipv6_Rule_Acl(NosDeviceAction):

    def run(self, mgmt_ip, username, password, acl_name, seq_id,
            action, protocol_type, source, destination, dscp,
            drop_precedence_force, urg, ack, push, fin, rst, sync,
            vlan_id, count, log, mirror, copy_sflow, dscp_marking,
            fragment, drop_precedence, icmp_filter, tcp_operator, acl_rules):

        """Run helper methods to add an L3 IPV6 ACL rule to an existing ACL
        """

        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as e:
            self.logger.error(e.message)
            sys.exit(-1)
        return self.switch_operation(acl_name, seq_id, action, protocol_type,
                                     source, destination, dscp,
                                     drop_precedence_force, urg, ack, push,
                                     fin, rst, sync, vlan_id, count, log,
                                     mirror, copy_sflow, dscp_marking, fragment,
                                     drop_precedence, icmp_filter, tcp_operator,
                                     acl_rules)

    @log_exceptions
    def switch_operation(self, acl_name, seq_id, action, protocol_type,
                         source, destination, dscp, drop_precedence_force,
                         urg, ack, push, fin, rst, sync, vlan_id, count,
                         log, mirror, copy_sflow, dscp_marking, fragment,
                         drop_precedence, icmp_filter, tcp_operator,
                         acl_rules):
        params_config = locals()
        params_config.pop('self', None)

        with self.pmgr(conn=self.conn, auth=self.auth,
                       auth_snmp=self.auth_snmp,
                       connection_type='NETCONF') as device:
            # pylint: disable=no-member
            if acl_rules:
                output = device.acl.add_ipv6_rule_acl_bulk(acl_name=acl_name,
                                                           acl_rules=acl_rules)
            else:
                output = device.acl.add_ipv6_rule_acl(**params_config)

            self.logger.info(output)
            return True

        return False
