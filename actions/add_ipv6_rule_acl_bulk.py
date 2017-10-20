from ne_base import NosDeviceAction
from ne_base import log_exceptions
import re


class Add_Ipv6_Rule_Acl_Bulk(NosDeviceAction):
    def run(self, mgmt_ip, username, password, acl_name, acl_rules):
        """Run helper methods to add an L3 IPV6 ACL rule to an existing ACL
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        return self.switch_operation(acl_name, acl_rules)

    @log_exceptions
    def switch_operation(self, acl_name, acl_rules):
        seqs_list = []
        seq_id_next = 10
        seq_id_fetched = False
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

            for rule in acl_rules:
                seq_id = rule.pop('seq_id', None)
                action = rule.pop('action', 'permit')
                protocol_type = rule.pop('protocol_type', None)
                source = rule.pop('source', 'any')
                destination = rule.pop('destination', None)
                dscp = rule.pop('dscp', None)
                drop_precedence_force = rule.pop('drop_precedence_force', None)
                urg = rule.pop('urg', False)
                ack = rule.pop('ack', False)
                push = rule.pop('push', False)
                fin = rule.pop('fin', False)
                rst = rule.pop('rst', False)
                sync = rule.pop('sync', False)
                vlan = rule.pop('vlan_id', None)
                count = rule.pop('count', False)
                log = rule.pop('log', False)
                mirror = rule.pop('mirror', False)
                copy_sflow = rule.pop('copy_sflow', False)
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
                    raise ValueError('drop_precedence_force cannot be given for standard ACL')
                elif acl_type == 'standard' and any([urg, ack, push, fin, rst, sync, mirror]):
                    raise ValueError('Any of (urg, ack, push, fin, rst, sync, mirror)'
                                     ' cannot be given for standard access list')
                any([action, count, log])
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
                seqs_list.append(seq_dict)
            return self._add_ipv6_acl_rules(device,
                                            acl_name=acl_name,
                                            acl_type=acl_type,
                                            address_type=address_type,
                                            seqs_list=seqs_list)

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

    def _add_ipv6_acl_rules(self, device, acl_name, acl_type, address_type, seqs_list):
        result = {}
        for seq_dict in seqs_list:
            self.logger.info('Adding rule on ACL %s at seq_id %s',
                             acl_name, str(seq_dict['seq_id']))
            output = device.acl.add_acl_rule(acl_name=acl_name,
                                             acl_type=acl_type,
                                             address_type=address_type,
                                             seqs_list=[seq_dict])
            self.logger.info(output)
            result['Seq-%s' % str(seq_dict['seq_id'])] = True
        return result
