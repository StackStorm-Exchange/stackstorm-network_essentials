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
        with self.pmgr(conn=self.conn, auth=self.auth, connection_type='NETCONF') as device:
            try:
                acl = device.acl.get_acl_type(acl_name)
                address_type = acl['protocol']
                acl_type = acl['type']
                self.logger.info('Successfully identified the acl_type as %s (%s)',
                                 acl_type, address_type)
                return self._delete_acl(device, address_type, acl_type, acl_name)
            except ValueError as e:
                if 'Failed to identify acl_type' in e.message:
                    self.logger.info("ACL %s does not exist", acl_name)
                else:
                    raise

    def _delete_acl(self, device, address_type, acl_type, acl_name):
        self.logger.info('Deleting ACL %s', acl_name)
        output = device.acl.delete_acl(address_type=address_type,
                                       acl_type=acl_type, acl_name=acl_name)
        self.logger.info(output)
        return True
