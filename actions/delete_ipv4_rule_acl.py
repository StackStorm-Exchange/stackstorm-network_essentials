from ne_base import NosDeviceAction


class Delete_Ipv4_Rule_Acl(NosDeviceAction):
    def run(self, mgmt_ip, username, password, acl_name, seq_id):
        """Run helper methods to delete an L3 IPV4 ACL rule of an existing ACL.

        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        try:
            device = self.asset(ip_addr=self.host, auth=self.auth)
            self.logger.info('successfully connected to %s to enable interface', self.host)
        except AttributeError as e:
            raise ValueError('Failed to connect to %s due to %s', self.host, e.message)
        except ValueError as verr:
            self.logger.error("Error while logging in to %s due to %s",
                              self.host, verr.message)
            raise ValueError("Error while logging in to %s due to %s",
                             self.host, verr.message)
        except self.ConnectionError as cerr:
            self.logger.error("Connection failed while logging in to %s due to %s",
                              self.host, cerr.message)
            raise ValueError("Connection failed while logging in to %s due to %s",
                             self.host, cerr.message)
        except self.RestInterfaceError as rierr:
            self.logger.error("Failed to get a REST response while logging in "
                              "to %s due to %s", self.host, rierr.message)
            raise ValueError("Failed to get a REST response while logging in "
                             "to %s due to %s", self.host, rierr.message)
        seq = []
        output = {}
        seq_variables_std = ('seq-id', 'action', 'src-host-any-sip', 'src-host-ip', 'src-mask',
                             'count', 'log')
        seq_variables_ext = ('seq-id', 'action', 'protocol-type', 'src-host-any-sip',
                             'src-host-ip', 'src-mask', 'sport', 'sport-number-eq-neq-tcp',
                             'sport-number-lt-tcp', 'sport-number-gt-tcp',
                             'sport-number-eq-neq-udp', 'sport-number-lt-udp',
                             'sport-number-gt-udp', 'sport-number-range-lower-tcp',
                             'sport-number-range-lower-udp', 'sport-number-range-higher-tcp',
                             'sport-number-range-higher-udp', 'dst-host-any-dip', 'dst-host-ip',
                             'dst-mask', 'dport', 'dport-number-eq-neq-tcp',
                             'dport-number-lt-tcp', 'dport-number-gt-tcp',
                             'dport-number-eq-neq-udp', 'dport-number-lt-udp',
                             'dport-number-gt-udp', 'dport-number-range-lower-tcp',
                             'dport-number-range-lower-udp', 'dport-number-range-higher-tcp',
                             'dport-number-range-higher-udp', 'dscp', 'urg', 'ack', 'push',
                             'fin', 'rst', 'sync', 'vlan', 'count', 'log')

        acl_type = self._get_acl_type_(device, acl_name)['type']
        self.logger.info('successfully identified the acl_type as %s', acl_type)
        if acl_type == 'standard':
            seq_variables = seq_variables_std
        elif acl_type == 'extended':
            seq_variables = seq_variables_ext

        seq_dict = self._get_seq_(device,
                                  acl_name=acl_name,
                                  acl_type=acl_type,
                                  seq_id=seq_id)
        for v in seq_variables:
            try:
                seq.append(seq_dict[v])
            except:
                seq.append(None)

        try:
            changes = self._delete_ipv4_acl_(device,
                                             acl_name=acl_name,
                                             acl_type=acl_type,
                                             seq=tuple(seq))
        except Exception as msg:
            self.logger.error(msg)
            raise ValueError(msg)
        output['result'] = changes
        self.logger.info('closing connection to %s after adding rule access-list--all done!',
                         self.host)
        return output

    def _delete_ipv4_acl_(self, device, acl_name, acl_type, seq):
        self.logger.info('Deleting rule on access list- %s at seq_id %s',
                         acl_name, seq[0])
        result = 'False'
        try:
            if acl_type == 'standard':
                delete_acl = device.ip_access_list_standard_seq_delete
            elif acl_type == 'extended':
                delete_acl = device.ip_access_list_extended_seq_delete
            aply = list(delete_acl(acl_name, seq))
            result = str(aply[0])
            if str(aply[0]) == 'False':
                self.logger.error('Cannot delete rule on %s due to %s', acl_name,
                                  str(aply[1][0][self.host]['response']['json']['output']))
            else:
                self.logger.info('Successfully deleted rule on %s on seq_id %s', acl_name, seq[0])
        except (AttributeError, ValueError) as e:
            self.logger.error('Cannot delete rule on %s due to %s', acl_name, e.message)
            raise ValueError(e.message)
        return result
