import re
from ne_base import NosDeviceAction
from ne_base import log_exceptions


class Add_Ipv6_Rule_Acl(NosDeviceAction):
    def run(self, mgmt_ip, username, password, acl_name, seq_id,
            action, protocol_type, source, destination, dscp, drop_precedence_force,
            urg, ack, push, fin, rst, sync, vlan_id, count, log, mirror, copy_sflow):
        """Run helper methods to apply IPv6 ACL on desired interface.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        return self.switch_operation(acl_name, seq_id, action, protocol_type,
                                     source, destination, dscp, drop_precedence_force,
                                     urg, ack, push, fin, rst, sync, vlan_id, count, log,
                                     mirror, copy_sflow)

    @log_exceptions
    def switch_operation(self, acl_name, seq_id, action, protocol_type,
                         source, destination, dscp, drop_precedence_force,
                         urg, ack, push, fin, rst, sync, vlan, count, log, mirror, copy_sflow):
        with self.pmgr(conn=self.conn, auth=self.auth, connection_type='NETCONF') as device:
            acl = device.acl.get_acl_type(acl_name)
            address_type = acl['protocol']
            acl_type = acl['type']
            self.logger.info('Successfully identified the acl_type as %s (%s)',
                             acl_type, address_type)

            if address_type is not 'ipv6':
                raise ValueError('ACL not compatible for adding IPV6 acl rule')

            if acl_type == 'standard':
                seq_variables = device.acl.seq_variables_ip_std
            elif acl_type == 'extended':
                seq_variables = device.acl.seq_variables_ip_ext
            if acl_type == 'extended' and destination is None:
                raise ValueError('Destination required in extended access list')
            elif acl_type == 'extended' and protocol_type is None:
                raise ValueError('protocol_type is required for extended access list')
            elif acl_type == 'standard' and destination:
                raise ValueError('Destination cannot be given for standard access list')
            elif acl_type == 'standard' and protocol_type:
                raise ValueError('protocol_type cannot be given for standard access list')
            elif acl_type == 'standard' and vlan:
                raise ValueError('vlan_id cannot be given for standard access list')
            elif acl_type == 'standard' and dscp:
                raise ValueError('dscp cannot be given for standard access list')
            elif acl_type == 'standard' and drop_precedence_force:
                raise ValueError('drop_precedence_force cannot be given for standard access list')
            elif acl_type == 'standard' and any([urg, ack, push, fin, rst, sync, mirror]):
                raise ValueError('Any of (urg, ack, push, fin, rst, sync, mirror)'
                                 ' cannot be given for standard access list')
            try:
                seq_dict = {key: None for key in seq_variables}
            except:
                raise ValueError('Cannot get seq_variables')

            seq_dict['user_seq_id'] = seq_id
            if seq_id is None:
                seq_id = device.acl.get_seq_id(acl_name, acl_type, address_type)
                if seq_id is None:
                    raise ValueError('Cannot get seq_id')
            self.logger.info('seq_id for the rule is %s', seq_id)
            src_dict = self._parse_(protocol_type, source, 'src', 'sip')
            if acl_type == 'extended':
                dst_dict = self._parse_(protocol_type, destination, 'dst', 'dip')
            for variable in seq_dict:
                if 'src' in variable or 'sport' in variable:
                    try:
                        seq_dict[variable] = src_dict[variable]
                    except:
                        pass
                elif 'dst' in variable or 'dport' in variable:
                    try:
                        seq_dict[variable] = dst_dict[variable]
                    except:
                        pass
                else:
                    try:
                        seq_dict[variable] = eval(variable)
                    except:
                        pass
            if dscp is not None and (' ' in dscp or ',' in dscp):
                dscp_vals = re.split(' |,', dscp)
                seq_dict['dscp'] = dscp_vals[0].strip()
                seq_dict['dscp-force'] = dscp_vals[1].strip()
            seq_dict['drop-precedence-force'] = drop_precedence_force
            seq_dict['copy-sflow'] = copy_sflow
            if seq_dict['drop-precedence-force'] is not None and \
               not re.match("^[0-2]$", seq_dict['drop-precedence-force']):
                        raise ValueError("Invalid \'drop-precedence-force\' value,"
                                         " 0-2 only supported")

            return self._add_ipv6_acl_rule(device,
                                           acl_name=acl_name,
                                           acl_type=acl_type,
                                           address_type=address_type,
                                           seq_dict=seq_dict)

    def _parse_(self, protocol_type, statement, key, tail):
        self.logger.info('parsing the %s statement', key)
        output = {}
        msg = None
        statement_list = statement.split(" ")
        map(lambda x: x.strip(",. \n-"), statement_list)
        if statement_list[0] == 'any' and len(statement_list) == 1:
            output[key + '_host_any_' + tail] = statement_list.pop(0)
        elif statement_list[0] == 'host':
            try:
                output[key + '_host_any_' + tail] = statement_list.pop(0)
                host_ip = statement_list.pop(0)
                if self._validate_ipv6_(host_ip):
                    output[key + '_host_ip'] = host_ip
                else:
                    msg = 'host ip in {} statement is invalid'.format(key)
            except:
                msg = 'host ip missing in {} statement'.format(key)
        elif self._validate_ip_network(statement_list[0]):
            output[key + '_host_any_' + tail] = statement_list.pop(0)
        else:
            msg = 'Incorrect {} statement'.format(key)
        if msg is not None:
            self.logger.error(msg)
            raise ValueError(msg)
        try:
            port = statement_list[0]
        except:
            return output
        if statement_list[0] in ['lt', 'gt', 'eq', 'range', 'neq']:
            output[key[:1] + 'port'] = port
            statement_list.pop(0)
            if port in ['eq', 'neq']:
                port = 'eq_neq'
            if port != 'range':
                try:
                    output[key[:1] + 'port_number_' + port +
                           '_' + protocol_type] = statement_list.pop(0)
                except:
                    msg = '{} port number {} missing'.format(key, port)
            else:
                try:
                    output[key[:1] + 'port_number_' + port + '_lower_' +
                           protocol_type] = statement_list.pop(0)
                    output[key[:1] + 'port_number_' + port + '_higher_' +
                           protocol_type] = statement_list.pop(0)
                except:
                    msg = '{} port numbers range missing'.format(key)

        else:
            msg = 'Incorrect {} statement'.format(key)

        if msg is not None:
            self.logger.error(msg)
            raise ValueError(msg)
        return output

    def _add_ipv6_acl_rule(self, device, acl_name, acl_type, address_type, seq_dict):
        self.logger.info('Adding rule on ACL %s at seq_id %s', acl_name, str(seq_dict['seq_id']))
        output = device.acl.add_acl_rule(acl_name=acl_name,
                                         acl_type=acl_type,
                                         address_type=address_type,
                                         seqs_list=[seq_dict])
        self.logger.info(output)
        return True
