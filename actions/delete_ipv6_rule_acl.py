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
        with self.pmgr(conn=self.conn, auth=self.auth, connection_type='NETCONF') as device:
            acl = device.acl.get_acl_type(acl_name)
            address_type = acl['protocol']
            acl_type = acl['type']
            self.logger.info('Successfully identified the acl_type as %s (%s)',
                             acl_type, address_type)

            if address_type is not 'ipv6':
                raise ValueError('ACL not compatible for IPV6 acl rule')

            if not seq_id:
                raise ValueError("Enter a valid seq_id to remove")
            seq_dict = device.acl.get_seq(acl_name, seq_id, acl_type, address_type)
            if not seq_dict:
                self.logger.info("ACL %s has no rule with seq_id %s" % (acl_name, seq_id))
                return None

            return self._delete_ipv6_acl_rule(device,
                                              acl_name=acl_name,
                                              acl_type=acl_type,
                                              address_type=address_type,
                                              seq_dict=seq_dict)

    def _delete_ipv6_acl_rule(self, device, acl_name, acl_type, address_type, seq_dict):
        self.logger.info('Deleting rule on access list- %s at seq_id %s',
                         acl_name, str(seq_dict['seq_id']))
        output = device.acl.remove_acl_rule(acl_name=acl_name,
                                            acl_type=acl_type,
                                            address_type=address_type,
                                            seqs_list=[seq_dict])
        self.logger.info(output)
        return True
