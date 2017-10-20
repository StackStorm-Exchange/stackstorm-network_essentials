from ne_base import NosDeviceAction
from ne_base import log_exceptions


class Delete_Rule_Acl(NosDeviceAction):
    def run(self, mgmt_ip, username, password, acl_name, seq_ids):
        """Run helper methods to delete arule of an existing ACL.

        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        return self.switch_operation(acl_name, seq_ids)

    @log_exceptions
    def switch_operation(self, acl_name, seq_ids):
        seqs_list = []
        with self.pmgr(conn=self.conn, auth=self.auth, connection_type='NETCONF') as device:
            acl = device.acl.get_acl_type(acl_name)
            address_type = acl['protocol']
            acl_type = acl['type']
            self.logger.info('Successfully identified the acl_type as %s (%s)',
                             acl_type, address_type)

            for seq_id in seq_ids:
                seq_dict = device.acl.get_seq(acl_name, seq_id, acl_type, address_type)
                if not seq_dict:
                    self.logger.info("ACL %s has no rule with seq_id %s" % (acl_name, seq_id))
                    continue

                seqs_list.append(seq_dict)

            return self._delete_ipv4_acl_rule(device,
                                              acl_name=acl_name,
                                              acl_type=acl_type,
                                              address_type=address_type,
                                              seqs_list=seqs_list)

    def _delete_ipv4_acl_rule(self, device, acl_name, acl_type, address_type, seqs_list):
        result = {}
        for seq_dict in seqs_list:
            self.logger.info('Deleting rule on ACL %s at seq_id %s',
                             acl_name, str(seq_dict['seq_id']))
            output = device.acl.remove_acl_rule(acl_name=acl_name,
                                                acl_type=acl_type,
                                                address_type=address_type,
                                                seqs_list=[seq_dict])
            self.logger.info(output)
            result['Seq-%s' % str(seq_dict['seq_id'])] = True
        return True
