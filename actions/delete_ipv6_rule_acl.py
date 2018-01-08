from ne_base import NosDeviceAction
from ne_base import log_exceptions


class Delete_Ipv6_Rule_Acl(NosDeviceAction):
    def run(self, mgmt_ip, username, password, acl_name, seq_id):
        """Run helper methods to delete an L3 IPV6 ACL rule of an existing ACL.

        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        return self.switch_operation(acl_name, seq_id)

    @log_exceptions
    def switch_operation(self, acl_name, seq_id):
        parameters = locals()
        parameters .pop('self', None)

        self.logger.info('delete_ipv6_rule_acl Operation: Initiated')
        with self.pmgr(conn=self.conn, auth=self.auth,
                       auth_snmp=self.auth_snmp,
                       connection_type='NETCONF') as device:

            self.logger.info('Deleting Rule from L2 ACL: {}'
                             .format(acl_name))

            if seq_id.isdigit():
                parameters['seq_id'] = int(parameters['seq_id'])
                output = device.acl.delete_ipv6_acl_rule(**parameters)
            else:
                output = device.acl.delete_ipv6_acl_rule_bulk(**parameters)

            self.logger.info(output)
            return True

        return False
