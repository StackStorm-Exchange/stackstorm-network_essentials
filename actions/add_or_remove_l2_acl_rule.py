from base1 import DeviceAction


class Add_Or_Remove_L2_Acl_Rule(DeviceAction):

    """
    standard rule elements --> seq_id, action, source, srchost, src_mac_addr_mask, count, log
    extended rule elements --> seq_id, action, source, srchost, src_mac_addr_mask, dst, dsthost,
                                dst_mac_addr_mask, ethertype, vlan, count, log
    """

    def run(self, to_remove, device_ip, username, password, l2_acl_name, seq_id,
        action, source, srchost, src_mac_addr_mask, dst, dsthost, dst_mac_addr_mask, ethertype,
            vlan, count, log):

        self.validate_input_parameters(to_remove, seq_id, source, srchost, src_mac_addr_mask,
            dst, dsthost, dst_mac_addr_mask, ethertype, vlan)

        device = self.device_login(device_ip, username, password)

        l2_acl_type = self.find_acl_type(device_ip, device, l2_acl_name)

        seq_id = self.find_seq_id(to_remove, seq_id, device_ip, device,
            l2_acl_name, l2_acl_type)

        if to_remove:
            self.remove_rule(device_ip, device, l2_acl_name, l2_acl_type, seq_id)
        else:
            self.add_rule(device_ip, device, l2_acl_name, l2_acl_type, seq_id, action,
                source, srchost, src_mac_addr_mask, dst, dsthost, dst_mac_addr_mask,
                ethertype, vlan, count, log)

    def device_login(self, device_ip, username, password):
        self.logger.debug('Trying to login to device %s', device_ip)
        self.setup_connection(host=device_ip, user=username, passwd=password)
        try:
            device = self.asset(ip_addr=self.host, auth=self.auth)
            self.logger.debug('Login to device %s is okay', device_ip)
        except Exception as e:
            raise ValueError('Failed to login to %s, error is %s', device_ip, e.message)
        return device

    def validate_input_parameters(self, to_remove, seq_id, source, srchost, src_mac_addr_mask,
            dst, dsthost, dst_mac_addr_mask, ethertype, vlan):

        self.logger.debug('Doing validations')
        # validations only for remove operation
        if to_remove:
            if seq_id is None:
                raise ValueError('Sequence id is not input, it is required for remove operation')

        # validations only for add operation, for remove operation these parameters are ignored
        if not to_remove:
            if source != 'any' and source != 'host':
                self.logger.debug('source is a MAC address')
                if not self.is_valid_mac(source):
                    raise ValueError('The format of source MAC address %s is invalid. \
                        Valid format is HHHH.HHHH.HHHH', source)

                if src_mac_addr_mask is None:
                    raise ValueError('The src_mac_addr_mask is required when source \
                        is a MAC address value')
                else:
                    if not self.is_valid_mac(src_mac_addr_mask):
                        raise ValueError('The format of src_mac_addr_mask %s is invalid. \
                            Valid format is HHHH.HHHH.HHHH', src_mac_addr_mask)

            if dst != 'any' and dst != 'host':
                self.logger.debug('dst is a MAC address')
                if not self.is_valid_mac(dst):
                    raise ValueError('The format of dst MAC address %s is invalid. \
                        Valid format is HHHH.HHHH.HHHH', dst)

                if dst_mac_addr_mask is None:
                    raise ValueError('The dst_mac_addr_mask is required when dst \
                        is a MAC address value')
                else:
                    if not self.is_valid_mac(dst_mac_addr_mask):
                        raise ValueError('The format of dst_mac_addr_mask %s is invalid. \
                            Valid format is HHHH.HHHH.HHHH', dst_mac_addr_mask)

            if ethertype != 'arp' and ethertype != 'fcoe' and ethertype != 'ipv4':
                try:
                    ethertype_id = (int(ethertype))
                except Exception as e:
                    raise ValueError('The ethertype %s is invalid, could not convert to integer',
                        ethertype)

                if ethertype_id < 1536 or ethertype_id > 65535:
                    raise ValueError('The ethertype %s is invalid, valid value is 1536-65535',
                        ethertype)

            if vlan is not None:
                try:
                    vlan_id = (int(vlan))
                except Exception as e:
                    raise ValueError('The vlan %s is invalid, could not convert to integer \
                        due to %s', vlan, e.message)

                if vlan_id < 1 or vlan_id > 4090:
                    raise ValueError('The vlan %s is invalid, valid value is 1-4090', vlan)

    def find_acl_type(self, device_ip, device, l2_acl_name):
        self.logger.debug('Trying to figure out if acl is standard or extended')
        if self.is_standard_l2_acl(device_ip, device, l2_acl_name):
            l2_acl_type = 'standard'
            self.logger.debug('The L2 acl %s is standard', l2_acl_name)
        elif self.is_extended_l2_acl(device_ip, device, l2_acl_name):
            l2_acl_type = 'extended'
            self.logger.debug('The L2 acl %s is extended', l2_acl_name)
        else:
            raise ValueError('The L2 acl %s does not exist', l2_acl_name)
        return l2_acl_type

    def find_seq_id(self, to_remove, seq_id, device_ip, device, l2_acl_name, l2_acl_type):
        self.logger.debug('Trying to figure out the sequence id')

        if not to_remove and seq_id is None:
                self.logger.debug('Sequence id is not input so generating a new sequence id')
                seq_id = self.get_next_seq_id(device_ip, device, l2_acl_name, l2_acl_type)
                if seq_id is None:
                    raise ValueError('Failed to get the next seq_id')

        self.logger.debug('Sequence id for the rule is %s', seq_id)
        return seq_id

    def remove_rule(self, device_ip, device, l2_acl_name, l2_acl_type, seq_id):
        self.logger.debug('Trying to remove rule with sequence id %s', seq_id)

        if l2_acl_type == 'standard':
            self.logger.debug('Removing rule from standard acl %s', l2_acl_name)

            try:
                post = device.mac_access_list_standard_seq_delete(standard=l2_acl_name,
                    seq=(seq_id, None, None, None, None, None, None))
            except Exception as e:
                raise ValueError('Failed to remove rule from %s due to %s', l2_acl_name, e.message)

            self.check_status_code(post, device_ip)

        elif l2_acl_type == 'extended':
            self.logger.debug('Removing rule from extended acl %s', l2_acl_name)

            try:
                post = device.mac_access_list_extended_seq_delete(extended=l2_acl_name,
                    seq=(seq_id, None, None, None, None, None, None, None, None, None, None, None))
            except Exception as e:
                raise ValueError('Failed to remove rule from %s due to %s', l2_acl_name, e.message)

            self.check_status_code(post, device_ip)

    def add_rule(self, device_ip, device, l2_acl_name, l2_acl_type, seq_id, action,
        source, srchost, src_mac_addr_mask, dst, dsthost, dst_mac_addr_mask, ethertype,
            vlan, count, log):
        self.logger.debug('Trying to add rule')

        if l2_acl_type == 'standard':
            self.logger.debug('Adding rule to standard acl %s', l2_acl_name)

            try:
                post = device.mac_access_list_standard_seq_create(standard=l2_acl_name,
                    seq=(seq_id, action, source, srchost, src_mac_addr_mask, count, log))
            except Exception as e:
                raise ValueError('Failed to add rule to %s due to %s', l2_acl_name, e.message)

            self.check_status_code(post, device_ip)
        elif l2_acl_type == 'extended':
            self.logger.debug('Adding rule to extended acl %s', l2_acl_name)

            try:
                post = device.mac_access_list_extended_seq_create(extended=l2_acl_name,
                    seq=(seq_id, action, source, srchost, src_mac_addr_mask, dst, dsthost,
                        dst_mac_addr_mask, ethertype, vlan, count, log))
            except Exception as e:
                raise ValueError('Failed to add rule to %s due to %s', l2_acl_name, e.message)

            self.check_status_code(post, device_ip)

    def check_status_code(self, operation, device_ip):
        status_code = operation[1][0][device_ip]['response']['status_code']
        self.logger.debug("Operation returned %s", status_code)
        if status_code >= 400:
            error_msg = operation[1][0][device_ip]['response']['text']
            raise ValueError(error_msg)

    def is_standard_l2_acl(self, device_ip, device, l2_acl_name):
        try:
            get = device.mac_access_list_standard_get(standard=l2_acl_name)
            type = str(get[1][0][device_ip]['response']['json']['output'].keys()[0])
            if type == 'standard':
                self.logger.debug('is_standard_l2_acl - returning True for %s', l2_acl_name)
                return True
            else:
                self.logger.debug('is_standard_l2_acl - returning False for %s', l2_acl_name)
                return False
        except Exception as e:
            self.logger.debug('Exception in is_standard_l2_acl - returning False %s', e.message)
            return False

    def is_extended_l2_acl(self, device_ip, device, l2_acl_name):
        try:
            get = device.mac_access_list_extended_get(extended=l2_acl_name)
            type = str(get[1][0][device_ip]['response']['json']['output'].keys()[0])
            if type == 'extended':
                self.logger.debug('is_extended_l2_acl - returning True for %s', l2_acl_name)
                return True
            else:
                self.logger.debug('is_extended_l2_acl - returning False for %s', l2_acl_name)
                return False
        except Exception as e:
            self.logger.debug('exception in is_extended_l2_acl - returning False %s', e.message)
            return False

    def get_next_seq_id(self, device_ip, device, l2_acl_name, l2_acl_type):
        try:
            if l2_acl_type == 'standard':
                get = device.mac_access_list_standard_get(standard=l2_acl_name)
            elif l2_acl_type == 'extended':
                get = device.mac_access_list_extended_get(extended=l2_acl_name)

            rules_list = get[1][0][device_ip]['response']['json']['output'][l2_acl_type]

            if 'seq' in rules_list:
                seq_list = rules_list['seq']
                if type(seq_list) == list:
                    last_seq_id = int(seq_list[len(seq_list) - 1]['seq-id'])
                else:
                    last_seq_id = int(seq_list['seq-id'])

                if last_seq_id % 10 == 0:  # divisible by 10
                    seq_id = last_seq_id + 10
                else:
                    seq_id = (last_seq_id + 9) // 10 * 10  # rounding up to the nearest 10
            else:
                seq_id = 10

            return seq_id
        except Exception as e:
            self.logger.debug('exception in get_next_seq_id - %s', e.message)
            return None
