from ne_base import NosDeviceAction
from ne_base import log_exceptions


class Delete_Ipv4_Rule_Acl(NosDeviceAction):
    def run(self, mgmt_ip, username, password, acl_name, seq_id):
        """Run helper methods to delete an L3 IPV4 ACL rule of an existing ACL.

        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        return self.switch_operation(acl_name, seq_id)

    @log_exceptions
    def switch_operation(self, acl_name, seq_id):
        parameters = locals()
        parameters .pop('self', None)

        self.logger.info('add_or_remove_l2_acl_rule Operation: Initiated')
        with self.pmgr(conn=self.conn, auth=self.auth,
                       auth_snmp=self.auth_snmp,
                       connection_type='NETCONF') as device:

            self.logger.info('Deleting Rule from L2 ACL: {}'
                             .format(acl_name))
            output = device.acl.delete_ipv4_acl_rule(**parameters)

            self.logger.info(output)
            return True

        return False
