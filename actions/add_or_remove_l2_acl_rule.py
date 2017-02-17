import sys
from ne_base import NosDeviceAction


class Add_Or_Remove_L2_Acl_Rule(NosDeviceAction):

    """
    standard rule elements --> seq_id, action, source, srchost, src_mac_addr_mask, count, log
    extended rule elements --> seq_id, action, source, srchost, src_mac_addr_mask, dst, dsthost,
                                dst_mac_addr_mask, ethertype, vlan, count, log
    """

    def run(self, to_remove, mgmt_ip, username, password, acl_name, seq_id,
            action, source, srchost, src_mac_addr_mask, dst, dsthost, dst_mac_addr_mask,
            ethertype, vlan, count, log):
        """Run helper methods to add an L2 ACL rule to an existing ACL
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        device = self.get_device()
        seq = []
        output = {}
        seq_variables_std = ('seq_id', 'action', 'source', 'srchost',
                             'src_mac_addr_mask', 'count', 'log')
        seq_variables_ext = ('seq_id', 'action', 'source', 'srchost',
                             'src_mac_addr_mask', 'dst', 'dsthost',
                             'dst_mac_addr_mask', 'ethertype', 'vlan',
                             'count', 'log')
        try:
            acl = self._get_acl_type_(device, acl_name)
            self.logger.info('successfully identified the acl_type as %s', acl)
        except:
            self.logger.error('Failed to get access list. Check if ACL %s exists', acl_name)
            raise ValueError('Failed to get access list. Check if ACL exists')

        acl_type = acl['type']
        address_type = acl['protocol']
        if address_type is not 'mac':
            self.logger.error('%s is an %s ACL. Enter the mac ACL for adding rule',
                              acl_name, address_type)
            raise ValueError('ACL not compatible for adding L2 acl rule')

        if acl_type == 'standard':
            seq_variables = seq_variables_std
        elif acl_type == 'extended':
            seq_variables = seq_variables_ext

        if to_remove:
            if not seq_id:
                self.logger.error("Enter a valid seq_id to remove")
                sys.exit(-1)
            seq_dict = self._get_seq_(device,
                                      acl_name=acl_name,
                                      acl_type=acl_type,
                                      seq_id=seq_id,
                                      address_type='mac')
            if not seq_dict:
                self.logger.error("%s has no rule in seq_id %s", acl_name, seq_id)
                sys.exit(-1)

            # replacing the '-' in seq_variables with '_'
            for key, _ in seq_dict.iteritems():
                seq_dict[key.replace('-', '_')] = seq_dict.pop(key)
            for v in seq_variables:
                try:
                    seq.append(seq_dict[v])
                except:
                    seq.append(None)

            try:
                changes = self._delete_mac_acl_(device,
                                                acl_name=acl_name,
                                                acl_type=acl_type,
                                                seq=tuple(seq))
            except Exception as msg:
                self.logger.error(msg)
                raise ValueError(msg)

        else:
            if acl_type == 'extended' and not any([dst, dsthost, dst_mac_addr_mask]):
                self.logger.error('Destination required in extended access list')
                sys.exit(-1)
            elif acl_type == 'standard' and any([dst, dsthost, dst_mac_addr_mask]):
                self.logger.error('Destination cannot be given for standard access list')
                sys.exit(-1)

            try:
                seq_dict = {key: None for key in seq_variables}
            except:
                self.logger.error('Cannot get seq_variables')
                raise ValueError('Cannot get seq_variables')

            if seq_id is None:
                self.logger.info('seq_id not provided, getting the seq_id')
                seq_id = self._get_seq_id_(device, acl_name, acl_type, address_type)
                if seq_id is None:
                    self.logger.error('Cannot get seq_id')
                    raise ValueError('Cannot get seq_id')
            self.logger.info('seq_id for the rule is %s', seq_id)

            valid_src = self.validate_src_dst(source, srchost, src_mac_addr_mask, key='src')
            if not valid_src:
                raise ValueError("Invalid source parameters")

            valid_dst = self.validate_src_dst(dst, dsthost, dst_mac_addr_mask, key='dst')
            if not valid_dst:
                raise ValueError("Invalid dst parameters")

            if ethertype not in ["arp", "fcoe", "ipv4"]:
                try:
                    ethertype_id = (int(ethertype))
                except ValueError as verr:
                    self.logger.error("The ethertype value %s is invalid, could not convert to "
                                      "integer due to %s", ethertype, verr.message)
                    sys.exit(-1)
                if ethertype_id < 1536 or ethertype_id > 65535:
                    self.logger.error("The ethertype value %s is invalid, "
                                      "valid value is 1536-65535", ethertype)
                    sys.exit(-1)

            if vlan is not None:
                try:
                    vlan_id = (int(vlan))
                except ValueError as verr:
                    self.logger.error("The vlan value %s is invalid, could not convert to "
                                      "integer due to %s", vlan, verr.message)
                    sys.exit(-1)
                if vlan_id < 1 or vlan_id > 4090:
                    self.logger.error("The vlan %s is invalid, valid value is 1-4090", vlan)
                    sys.exit(-1)

            for variable in seq_dict:
                try:
                    seq_dict[variable] = eval(variable)
                except NameError:
                    pass

            for v in seq_variables:
                seq.append(seq_dict[v])
            try:
                changes = self._add_l2_acl_(device,
                                            acl_name=acl_name,
                                            acl_type=acl_type,
                                            seq=tuple(seq))
            except Exception as msg:
                self.logger.error(msg)
                raise ValueError(msg)

        output['result'] = changes
        self.logger.info('closing connection to %s --all done!',
                         self.host)
        return output

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

    def _add_l2_acl_(self, device, acl_name, acl_type, seq):
        self.logger.info('Adding rule on access list- %s',
                         acl_name)
        result = 'False'
        try:
            if acl_type == 'standard':
                add_acl = device.mac_access_list_standard_seq_create
            elif acl_type == 'extended':
                add_acl = device.mac_access_list_extended_seq_create
            else:
                self.logger.error('Invalid access list type %s', acl_type)
                raise ValueError('Invalid access list type %s', acl_type)
            aply = list(add_acl(acl_name, seq))
            result = str(aply[0])
            if not aply[0]:
                self.logger.error('Cannot add rule on %s due to %s', acl_name,
                                  str(aply[1][0][self.host]['response']['json']['output']))
                sys.exit(-1)
            else:
                self.logger.info('Successfully added rule on %s', acl_name)
        except (KeyError, AttributeError, ValueError) as e:
            self.logger.error('Cannot add rule on %s due to %s', acl_name, e.message)
            raise ValueError(e.message)
        return result

    def _delete_mac_acl_(self, device, acl_name, acl_type, seq):
        self.logger.info('Deleting rule on access list- %s at seq_id %s',
                         acl_name, seq[0])
        result = 'False'
        try:
            if acl_type == 'standard':
                delete_acl = device.mac_access_list_standard_seq_delete
            elif acl_type == 'extended':
                delete_acl = device.mac_access_list_extended_seq_delete
            aply = list(delete_acl(acl_name, seq))
            result = aply[0]
            if not aply[0]:
                self.logger.error('Cannot delete rule on %s due to %s', acl_name,
                                  str(aply[1][0][self.host]['response']['json']['output']))
            else:
                self.logger.info('Successfully deleted rule on %s on seq_id %s', acl_name, seq[0])
        except (AttributeError, ValueError) as e:
            self.logger.error('Cannot delete rule on %s due to %s', acl_name, e.message)
            raise ValueError(e.message)
        return result
