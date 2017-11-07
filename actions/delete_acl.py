from ne_base import NosDeviceAction
from ne_base import log_exceptions


class DeleteAcl(NosDeviceAction):
    """
    Deleting ipv4 and ipv6 ACL's
    """
    def run(self, mgmt_ip, username, password, acl_name):
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        return self.switch_operation(acl_name)

    @log_exceptions
    def switch_operation(self, acl_name):
        params_config = locals()
        params_config.pop('self', None)

        self.logger.info('Deleteng {} ACL'.format(acl_name))

        with self.pmgr(conn=self.conn, auth=self.auth,
                       auth_snmp=self.auth_snmp,
                       connection_type='NETCONF') as device:

            output = device.acl.delete_acl(**params_config)

            self.logger.info(output)
            return True

        return False
