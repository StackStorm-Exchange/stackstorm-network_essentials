from ne_base import NosDeviceAction
from ne_base import log_exceptions


class Add_Or_Remove_L2_Acl_Rule(NosDeviceAction):

    """
    standard rule elements -->
        seq_id, action, source, srchost, src_mac_addr_mask, count, log,
        copy_sflow
    extended rule elements -->
        seq_id, action, source, srchost, src_mac_addr_mask, dst, dsthost,
        dst_mac_addr_mask, vlan_tag_format, vlan, ethertype, arp_guard, pcp,
        drop_precedence_force, count, log, mirror, copy_sflow, drop_precedence,
        priority, priority, priority_force, priority_mapping
    """

    def run(self, delete, mgmt_ip, username, password, acl_name, seq_id,
            action, source, srchost, src_mac_addr_mask, dst, dsthost,
            dst_mac_addr_mask, vlan_tag_format, vlan, ethertype, arp_guard,
            pcp, drop_precedence_force, count, log, mirror, copy_sflow,
            drop_precedence, priority, priority_force, priority_mapping):
        """Run helper methods to add an L2 ACL rule to an existing ACL
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        return self.switch_operation(delete, acl_name, seq_id, action, source,
                                     srchost, src_mac_addr_mask, dst, dsthost,
                                     dst_mac_addr_mask, vlan_tag_format, vlan,
                                     ethertype, arp_guard, pcp,
                                     drop_precedence_force, count, log, mirror,
                                     copy_sflow, drop_precedence, priority,
                                     priority_force, priority_mapping)

    @log_exceptions
    def switch_operation(self, delete, acl_name, seq_id, action, source,
                         srchost, src_mac_addr_mask, dst, dsthost,
                         dst_mac_addr_mask, vlan_tag_format, vlan, ethertype,
                         arp_guard, pcp, drop_precedence_force, count, log,
                         mirror, copy_sflow, drop_precedence, priority,
                         priority_force, priority_mapping):

        parameters = locals()
        parameters .pop('self', None)

        self.logger.info('add_or_remove_l2_acl_rule Operation: Initiated')

        with self.pmgr(conn=self.conn, auth=self.auth,
                       auth_snmp=self.auth_snmp) as device:

            if delete:
                self.logger.info('Deleting Rule from L2 ACL: {}'
                                 .format(acl_name))

                output = device.acl.delete_l2_acl_rule(**parameters)
            else:
                self.logger.info('Adding Rule to L2 ACL: {}'
                                 .format(acl_name))

                output = device.acl.add_l2_acl_rule(**parameters)

            self.logger.info(output)
            return True

        return False
