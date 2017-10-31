from ne_base import NosDeviceAction
from ne_base import log_exceptions
import re


class Add_Mac_Rule_Acl_Bulk(NosDeviceAction):
    def run(self, mgmt_ip, username, password, acl_name, acl_rules):
        """Run helper methods to add an L2 ACL rule to an existing ACL
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        return self.switch_operation(acl_name, acl_rules)

    @log_exceptions
    def switch_operation(self, acl_name, acl_rules):
        seqs_list = []
        seq_id_next = 10
        seq_id_fetched = False
        with self.pmgr(conn=self.conn,
                       auth_snmp=self.auth_snmp, connection_type='NETCONF') as device:
            acl = device.acl.get_acl_type(acl_name)
            address_type = acl['protocol']
            acl_type = acl['type']
            self.logger.info('Successfully identified the acl_type as %s (%s)',
                             acl_type, address_type)

            if address_type is not 'mac':
                raise ValueError('ACL not compatible for adding L2 acl rule')

            if acl_type == 'standard':
                seq_variables = device.acl.seq_variables_mac_std
            elif acl_type == 'extended':
                seq_variables = device.acl.seq_variables_mac_ext

            for rule in acl_rules:
                seq_id = rule.pop('seq_id', None)
                action = rule.pop('action', 'deny')
                source = rule.pop('source', 'any')
                srchost = rule.pop('srchost', None)
                src_mac_addr_mask = rule.pop('src_mac_addr_mask', None)
                dst = rule.pop('dst', 'any')
                dsthost = rule.pop('dsthost', None)
                dst_mac_addr_mask = rule.pop('dst_mac_addr_mask', None)
                vlan_tag_format = rule.pop('vlan_tag_format', None)
                vlan = rule.pop('vlan', None)
                ethertype = rule.pop('ethertype', None)
                arp_guard = rule.pop('arp_guard', False)
                pcp = rule.pop('pcp', None)
                drop_precedence_force = rule.pop('drop_precedence_force', None)
                count = rule.pop('count', False)
                log = rule.pop('log', False)
                mirror = rule.pop('mirror', False)
                copy_sflow = rule.pop('copy_sflow', False)
                if acl_type == 'extended' and not any([dst, dsthost, dst_mac_addr_mask]):
                    raise ValueError('Destination required in extended access list')
                elif acl_type == 'standard' and any([dsthost, dst_mac_addr_mask]):
                    raise ValueError('Destination cannot be given for standard access list')
                any([action, count, log, mirror])
                try:
                    seq_dict = {key: None for key in seq_variables}
                except:
                    raise ValueError('Cannot get seq_variables')

                seq_dict['user_seq_id'] = seq_id
                if seq_id is None:
                    if not seq_id_fetched:
                        seq_id = device.acl.get_seq_id(acl_name, acl_type, address_type)
                        seq_id_fetched = True
                    if seq_id is None or seq_id < seq_id_next:
                        seq_id = seq_id_next
                if seq_id >= seq_id_next:
                    seq_id_next = (seq_id + 10) // 10 * 10
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
                        raise ValueError("The ethertype value %s is invalid, could not convert to"
                                         " integer due to %s" % (ethertype, verr.message))
                    if ethertype_id < 1536 or ethertype_id > 65535:
                        raise ValueError("The ethertype value %s is invalid, "
                                         "valid value is 1536-65535" % ethertype)
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
                seqs_list.append(seq_dict)

            return self._add_mac_acl_rules(device,
                                           acl_name=acl_name,
                                           acl_type=acl_type,
                                           address_type=address_type,
                                           seq_vars=seq_variables,
                                           seqs_list=seqs_list)

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

    def _add_mac_acl_rules(self, device, acl_name, acl_type, address_type, seq_vars, seqs_list):
        result = {}
        for seq_dict in seqs_list:
            self.logger.info('Adding rule on ACL %s at seq_id %s',
                             acl_name, str(seq_dict['seq_id']))
            output = device.acl.add_acl_rule(acl_name=acl_name,
                                             acl_type=acl_type,
                                             address_type=address_type,
                                             seq_vars=seq_vars,
                                             seqs_list=[seq_dict])
            self.logger.info(output)
            result['Seq-%s' % str(seq_dict['seq_id'])] = True
        return result
