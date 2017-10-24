import re
import sys
from ne_base import NosDeviceAction
from ne_base import log_exceptions


class Add_Or_Remove_L2_Acl_Rule(NosDeviceAction):

    """
    standard rule elements -->
        seq_id, action, source, srchost, src_mac_addr_mask, count, log, copy_sflow
    extended rule elements -->
        seq_id, action, source, srchost, src_mac_addr_mask, dst, dsthost, dst_mac_addr_mask,
        vlan_tag_format, vlan, ethertype, arp_guard, pcp, drop_precedence_force,
        count, log, mirror, copy_sflow
    """

    def run(self, delete, mgmt_ip, username, password, acl_name, seq_id,
            action, source, srchost, src_mac_addr_mask, dst, dsthost, dst_mac_addr_mask,
            vlan_tag_format, vlan, ethertype, arp_guard, pcp, drop_precedence_force,
            count, log, mirror, copy_sflow):
        """Run helper methods to add an L2 ACL rule to an existing ACL
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        return self.switch_operation(delete, acl_name, seq_id, action, source, srchost,
                                     src_mac_addr_mask, dst, dsthost, dst_mac_addr_mask,
                                     vlan_tag_format, vlan, ethertype, arp_guard, pcp,
                                     drop_precedence_force, count, log, mirror, copy_sflow)

    @log_exceptions
    def switch_operation(self, delete, acl_name, seq_id, action, source, srchost,
                         src_mac_addr_mask, dst, dsthost, dst_mac_addr_mask, vlan_tag_format,
                         vlan, ethertype, arp_guard, pcp, drop_precedence_force, count, log,
                         mirror, copy_sflow):
        with self.pmgr(conn=self.conn,
                       auth_snmp=self.auth_snmp, connection_type='NETCONF') as device:
            acl = device.acl.get_acl_type(acl_name)
            address_type = acl['protocol']
            acl_type = acl['type']
            self.logger.info('Successfully identified the acl_type as %s (%s)',
                             acl_type, address_type)

            if address_type is not 'mac':
                raise ValueError('ACL not compatible for L2 acl rule')

            if acl_type == 'standard':
                seq_variables = device.acl.seq_variables_mac_std
            elif acl_type == 'extended':
                seq_variables = device.acl.seq_variables_mac_ext

            if delete:
                if not seq_id:
                    self.logger.error("Enter a valid seq_id to remove")
                    sys.exit(-1)
                seq_dict = device.acl.get_seq(acl_name, seq_id, acl_type, address_type)
                if not seq_dict:
                    self.logger.info("ACL %s has no rule with seq_id %s" % (acl_name, seq_id))
                    return None

                # replacing the '-' in seq_variables with '_'
                for key, _ in seq_dict.iteritems():
                    seq_dict[key.replace('-', '_')] = seq_dict.pop(key)

                return self._delete_mac_acl_rule(device,
                                                 acl_name=acl_name,
                                                 acl_type=acl_type,
                                                 address_type=address_type,
                                                 seq_dict=seq_dict)

            else:
                if acl_type == 'extended' and not any([dst, dsthost, dst_mac_addr_mask]):
                    self.logger.error('Destination required in extended access list')
                    sys.exit(-1)
                elif acl_type == 'standard' and any([dsthost, dst_mac_addr_mask]):
                    self.logger.error('Destination cannot be given for standard access list')
                    sys.exit(-1)

                try:
                    seq_dict = {key: None for key in seq_variables}
                except:
                    self.logger.error('Cannot get seq_variables')
                    raise ValueError('Cannot get seq_variables')

                seq_dict['user_seq_id'] = seq_id
                if seq_id is None:
                    self.logger.info('seq_id not provided, getting the seq_id')
                    seq_id = device.acl.get_seq_id(acl_name, acl_type, address_type)
                    if seq_id is None:
                        raise ValueError('Cannot get seq_id')
                self.logger.info('seq_id for the rule is %s', seq_id)

                valid_src = self.validate_src_dst(source, srchost, src_mac_addr_mask, key='src')
                if not valid_src:
                    raise ValueError("Invalid source parameters")

                valid_dst = self.validate_src_dst(dst, dsthost, dst_mac_addr_mask, key='dst')
                if not valid_dst:
                    raise ValueError("Invalid dst parameters")

                if ethertype and ethertype not in ["arp", "fcoe", "ipv4"]:
                    try:
                        ethertype_id = (int(ethertype))
                    except ValueError as verr:
                        self.logger.error("The ethertype value %s is invalid, could not convert to"
                                          " integer due to %s", ethertype, verr.message)
                        sys.exit(-1)
                    if ethertype_id < 1536 or ethertype_id > 65535:
                        self.logger.error("The ethertype value %s is invalid, "
                                          "valid value is 1536-65535", ethertype)
                        sys.exit(-1)

                seq_dict['vlan'] = seq_dict['vlan-id-mask'] = None
                seq_dict['outer-vlan'] = seq_dict['outer-vlan-id-mask'] = None
                seq_dict['inner-vlan'] = seq_dict['inner-vlan-id-mask'] = None
                seq_dict['pcp'] = seq_dict['pcp-force'] = None
                for variable in seq_dict:
                    try:
                        seq_dict[variable] = eval(variable)
                    except:
                        pass
                if vlan is not None and (' ' in vlan or ',' in vlan):
                    vlan_vals = re.split(' |,', vlan)
                    vlan_vals = map(lambda x: x.strip(",. \n-"), vlan_vals)
                    if vlan_tag_format == 'double-tagged':
                        seq_dict['vlan'] = None
                        seq_dict['outer-vlan'] = vlan_vals[0]
                        seq_dict['outer-vlan-id-mask'] = \
                            vlan_vals[1] if '0x' in vlan_vals[1].lower() else None
                        seq_dict['inner-vlan'] = \
                            vlan_vals[2] if len(vlan_vals) > 2 and \
                            '0x' in vlan_vals[1].lower() else vlan_vals[1]
                        if len(vlan_vals) > 2:
                            seq_dict['inner-vlan-id-mask'] = \
                                vlan_vals[3] if len(vlan_vals) > 3 else vlan_vals[2]
                        if seq_dict['inner-vlan'] == seq_dict['inner-vlan-id-mask']:
                            seq_dict['inner-vlan-id-mask'] = None
                    else:
                        seq_dict['vlan'] = vlan_vals[0]
                        seq_dict['vlan-id-mask'] = vlan_vals[1]

                if pcp is not None and (' ' in pcp or ',' in pcp):
                    pcp_vals = re.split(' |,', pcp)
                    seq_dict['pcp'] = pcp_vals[0].strip()
                    seq_dict['pcp-force'] = pcp_vals[1].strip()
                seq_dict['vlan-tag-format'] = vlan_tag_format
                seq_dict['arp-guard'] = arp_guard
                seq_dict['drop-precedence-force'] = drop_precedence_force
                seq_dict['copy-sflow'] = copy_sflow
                if seq_dict['vlan'] is not None and \
                    not re.match("^(any)|(([1-9][0-9]{0,2})|([1-3][0-9]{3})|" +
                                 "(40[0-8][0-9])|(409[0-4]))$", seq_dict['vlan']):
                        raise ValueError("Invalid \'vlan\' value,"
                                         " any or 1-4096 only supported")
                if seq_dict['vlan-id-mask'] is not None and \
                   not re.match("^0x([0-9a-fA-F]{3})$", seq_dict['vlan-id-mask']):
                        raise ValueError("Invalid \'vlan-id-mask\' value,"
                                         " 0xHHH (3 digit hex value) only supported")
                if seq_dict['outer-vlan'] is not None and \
                    not re.match("^(any)|(([1-9][0-9]{0,2})|([1-3][0-9]{3})|"
                                 "(40[0-8][0-9])|(409[0-4]))$", seq_dict['outer-vlan']):
                        raise ValueError("Invalid \'outer-vlan\' value,"
                                         " any or 1-4096 only supported")
                if seq_dict['outer-vlan-id-mask'] is not None and \
                   not re.match("^0x([0-9a-fA-F]{3})$", seq_dict['outer-vlan-id-mask']):
                        raise ValueError("Invalid \'outer-vlan-id-mask\' value,"
                                         " 0xHHH (3 digit hex value) only supported")
                if seq_dict['inner-vlan'] is not None and \
                    not re.match("^(any)|(([1-9][0-9]{0,2})|([1-3][0-9]{3})|"
                                 "(40[0-8][0-9])|(409[0-4]))$", seq_dict['inner-vlan']):
                        raise ValueError("Invalid \'inner-vlan\' value,"
                                         " any or 1-4096 only supported")
                if seq_dict['inner-vlan-id-mask'] is not None and \
                   not re.match("^0x([0-9a-fA-F]{3})$", seq_dict['inner-vlan-id-mask']):
                        raise ValueError("Invalid \'inner-vlan-id-mask\' value,"
                                         " 0xHHH (3 digit hex value) only supported")
                if seq_dict['pcp'] is not None and not re.match("^[0-7]$", seq_dict['pcp']):
                        raise ValueError("Invalid \'pcp\' value, 0-7 only supported")
                if seq_dict['pcp-force'] is not None and \
                   not re.match("^[0-7]$", seq_dict['pcp-force']):
                        raise ValueError("Invalid \'pcp-force\' value, 0-7 only supported")
                if seq_dict['drop-precedence-force'] is not None and \
                   not re.match("^[0-2]$", seq_dict['drop-precedence-force']):
                        raise ValueError("Invalid \'drop-precedence-force\' value,"
                                         " 0-2 only supported")

                return self._add_l2_acl_rule(device,
                                             acl_name=acl_name,
                                             acl_type=acl_type,
                                             address_type=address_type,
                                             seq_dict=seq_dict)

    def validate_src_dst(self, src_dst, src_dst_host, mac_addr_mask, key):
        if src_dst != "any" and src_dst != "host":
            self.logger.debug("%s is a MAC address", key)
            if not self.is_valid_mac(src_dst):
                self.logger.error("The format of %s MAC address %s is invalid. "
                                  "Valid format is HHHH.HHHH.HHHH", key, src_dst)
                return False

            if mac_addr_mask is None:
                self.logger.error("The %s_mac_addr_mask is required when %s "
                                  "is a MAC address value", key, key)
                return False
            elif src_dst_host:
                self.logger.error("The %shost can't be entered when %s "
                                  "is a MAC address value", key, key)
                return False
            elif not self.is_valid_mac(mac_addr_mask):
                self.logger.error("The format of %s_mac_addr_mask %s is invalid. "
                                  "Valid format is HHHH.HHHH.HHHH", key, mac_addr_mask)
                return False
        elif src_dst == "host":
            if mac_addr_mask:
                self.logger.error("Can't enter %s_mac_addr_mask when %s is host",
                                  key, key)
                return False
            elif not src_dst_host:
                self.logger.error("Need a valid mac address in %shost when %s is host",
                                  key, key)
                return False
        return True

    def _add_l2_acl_rule(self, device, acl_name, acl_type, address_type, seq_dict):
        self.logger.info('Adding rule on ACL %s at seq_id %s', acl_name, str(seq_dict['seq_id']))
        output = device.acl.add_acl_rule(acl_name=acl_name,
                                         acl_type=acl_type,
                                         address_type=address_type,
                                         seqs_list=[seq_dict])
        self.logger.info(output)
        return True

    def _delete_mac_acl_rule(self, device, acl_name, acl_type, address_type, seq_dict):
        self.logger.info('Deleting rule on ACL %s at seq_id %s', acl_name, str(seq_dict['seq_id']))
        output = device.acl.remove_acl_rule(acl_name=acl_name,
                                            acl_type=acl_type,
                                            address_type=address_type,
                                            seqs_list=[seq_dict])
        self.logger.info(output)
        return True
