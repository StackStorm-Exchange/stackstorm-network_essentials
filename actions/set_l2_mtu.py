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
        with self.pmgr(conn=self.conn, auth=self.auth) as device:

            self.logger.info(
                'successfully connected to %s to set mtu',
                self.host)

            for interface in port_list:
                intf = str(interface)
                if "-" not in intf:
                    interface_list.append(intf)
                else:
                    ex_intflist = self.extend_interface_range(
                        intf_type=intf_type, intf_name=intf)
                    for ex_intf in ex_intflist:
                        interface_list.append(str(ex_intf))
            msg = None
            for intf in interface_list:

                if not self.validate_interface(intf_type, intf):
                    msg = "Input is not a valid Interface"
                    self.logger.error(msg)
                    raise ValueError(msg)

            if msg is None:
                changes = self._set_l2_mtu(device, intf_type=intf_type,
                                           intf_name=interface_list,
                                           mtu_size=mtu_size)
            output['result'] = changes
            self.logger.info('closing connection to %s after configuring'
                             ' L2 mtu on interface--'
                             ' all done!', self.host)
        return output

    def _set_l2_mtu(self, device, intf_type, intf_name, mtu_size):
        result = True
        for intf in intf_name:
            self.logger.info('configuring mtu_size %i on int-type - %s '
                             'int-name- %s',
                             mtu_size, intf_type, intf)
            try:

                device.interface.mtu(mtu=mtu_size,
                                     name=intf,
                                     int_type=intf_type)

                self.logger.info('Successfully  set  mtu_size %i on int %s %s',
                                 mtu_size, intf_type, intf)
            except (TypeError, AttributeError, ValueError) as e:
                self.logger.error('Cannot set L2 mtu on interface %s %s'
                                  ' due to %s',
                                  intf_type, intf, e.message)
                result = False
                raise ValueError(e.message)
        return result
