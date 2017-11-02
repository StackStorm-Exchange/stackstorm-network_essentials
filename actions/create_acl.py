from ne_base import NosDeviceAction
from ne_base import log_exceptions


class CreateAcl(NosDeviceAction):
    """
    Creating mac ipv4 and ipv6 ACLs
    """

    def run(self, mgmt_ip, username, password, address_type,
            acl_type, acl_name):

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        return self.switch_operation(address_type, acl_type, acl_name)

    @log_exceptions
    def switch_operation(self, address_type, acl_type, acl_name):
        params_config = locals()
        params_config.pop('self', None)

        self.logger.info('Creating %s ACL %s of type %s',
                         address_type, acl_name, acl_type)


        with self.pmgr(conn=self.conn, auth=self.auth,
                       auth_snmp=self.auth_snmp) as device:

            output = device.acl.create_acl(**params_config)
            self.logger.info(output)
            return True

        return False
