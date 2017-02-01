from ne_base import NosDeviceAction


class set_l2_mtu(NosDeviceAction):
    def run(self, mgmt_ip, username, password, intf_type, port_list, mtu_size):
        """Run helper methods to set L2 MTU on desired interface.
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
        for intf in port_list:
            if "-" not in intf:
                interface_list.append(intf)
            else:
                ex_intflist = self.extend_interface_range(intf_type=intf_type, intf_name=intf)
                for ex_intf in ex_intflist:
                    interface_list.append(ex_intf)
        msg = None
        for intf in interface_list:
            if not self.validate_interface(intf_type, intf):
                msg = "Input is not a valid Interface"
                self.logger.error(msg)
                raise ValueError(msg)

        if not 1522 <= mtu_size <= 9216:
            msg = "Invalid MTU size"
            self.logger.error(msg)
            raise ValueError(msg)

        if msg is None:
            changes = self._set_l2_mtu(device, intf_type=intf_type,
                                       intf_name=interface_list,
                                       mtu_size=mtu_size)
        output['result'] = changes
        self.logger.info('closing connection to %s after configuring L2 mtu on interface--'
                         ' all done!', self.host)
        return output

    def _set_l2_mtu(self, device, intf_type, intf_name, mtu_size):
        result = []
        for intf in intf_name:
            self.logger.info('configuring mtu_size %i on int-type - %s int-name- %s',
                             mtu_size, intf_type, intf)
            try:
                set_mtu = self._interface_update(device=device, intf_type=intf_type,
                                                 intf_name=intf, mtu=mtu_size)
                result.append(set_mtu)
                if not set_mtu:
                    self.logger.error('Cannot set L2 mtu on interface %s %s', intf_type, intf)
                else:
                    self.logger.info('Successfully  set  mtu_size %i on int %s %s',
                                     mtu_size, intf_type, intf)
            except (TypeError, AttributeError, ValueError) as e:
                self.logger.error('Cannot set L2 mtu on interface %s %s due to %s',
                                  intf_type, intf, e.message)
                raise ValueError(e.message)
        return result
