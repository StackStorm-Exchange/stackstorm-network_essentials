from ne_base import NosDeviceAction


class APPLY_ACL(NosDeviceAction):
    def run(self, mgmt_ip, username, password, intf_type, intf_name,
            rbridge_id, acl_name, acl_direction, traffic_type):
        """Run helper methods to apply ACL on desired interface.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        output = {}
        changes = []
        interface_list = []
        intf_type = intf_type.lower()
        try:
            device = self.asset(ip_addr=self.host, auth=self.auth)
            self.logger.info('successfully connected to %s to enable interface', self.host)
        except AttributeError as e:
            self.logger.error('Failed to connect to %s due to %s', self.host, e.message)
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
        ag_type = self._get_acl_type_(device, acl_name)['protocol']
        self.logger.info('successfully identified the access group type as %s', ag_type)
        # Check is the user input for Interface Name is correct
        for intf in intf_name:
            if "-" not in intf:
                interface_list.append(intf)
            else:
                ex_intflist = self.extend_interface_range(intf_type=intf_type, intf_name=intf)
                for ex_intf in ex_intflist:
                    interface_list.append(ex_intf)
        msg = None
        for intf in interface_list:
            if not self.validate_interface(intf_type, intf, rbridge_id):
                msg = "Input is not a valid Interface"
                self.logger.error(msg)
                raise ValueError(msg)
        if msg is None:
            changes = self._apply_acl(device, intf_type=intf_type,
                                      intf_name=interface_list,
                                      rbridge_id=rbridge_id,
                                      acl_name=acl_name,
                                      acl_direction=acl_direction,
                                      ag_type=ag_type,
                                      traffic_type=traffic_type)
        output['result'] = changes
        self.logger.info('closing connection to %s after removing access-list-- \
                      all done!', self.host)
        return output

    def _apply_acl(self, device, intf_type, intf_name, rbridge_id,
                   acl_name, acl_direction, ag_type, traffic_type):
        result = []
        for intf in intf_name:
            method = 'rbridge_id_interface_{}_{}_access_group_create'. \
                format(intf_type, ag_type) if rbridge_id \
                else 'interface_{}_{}_access_group_create'.format(intf_type, ag_type)

            aply_acl = eval('device.{}'.format(method))
            access_grp = (acl_name, acl_direction, traffic_type)
            self.logger.info('Applying ACL %s on int-type - %s int-name- %s',
                             acl_name, intf_type, intf)
            try:
                aply = list(aply_acl(rbridge_id, intf, access_grp)
                            if rbridge_id else list(aply_acl(intf, access_grp)))
                result.append(str(aply[0]))
                if not aply[0]:
                    self.logger.error('Cannot apply  %s on interface %s %s due to %s', acl_name,
                                      intf_type, intf, str(aply[1][0][self.host]
                                                           ['response']['json']['output']))
                else:
                    self.logger.info('Successfully  applied  %s ACL on interface %s %s ',
                                     acl_name, intf_type, intf)
            except (AttributeError, ValueError) as e:
                self.logger.error('Cannot apply %s on interface %s %s due to %s',
                                  acl_name, intf_type, intf, e.message)
                raise ValueError(e.message)
        return result
