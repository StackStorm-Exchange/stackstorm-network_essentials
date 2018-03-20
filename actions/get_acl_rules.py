import sys
from ne_base import NosDeviceAction
from ne_base import log_exceptions


class GetAclRules(NosDeviceAction):
    """
    Get ACL Rules created for this access-list.
    """
    def run(self, mgmt_ip, username, password, acl_name, seq_id):
        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as e:
            self.logger.error(e.message)
            sys.exit(-1)
        return self.switch_operation(acl_name, seq_id)

    @log_exceptions
    def switch_operation(self, acl_name, seq_id):
        params_config = locals()
        params_config.pop('self', None)

        self.logger.info('Getting rules for ACL {}'.format(acl_name))

        with self.pmgr(conn=self.conn, auth=self.auth,
                       auth_snmp=self.auth_snmp,
                       connection_type='NETCONF') as device:

            if device.connection_type == 'NETCONF':
                params_config['device'] = device

            output = device.acl.get_acl_rules(**params_config)

            # self.logger.info(output)
            return output
