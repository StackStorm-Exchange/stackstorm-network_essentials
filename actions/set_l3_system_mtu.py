from ne_base import NosDeviceAction


class set_l3_system_mtu(NosDeviceAction):
    def run(self, mgmt_ip, username, password, ip_type, mtu_size):
        """Run helper methods to set system L3 MTU on.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        output = {}
        changes = []
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
        msg = None
        if not 1300 <= mtu_size <= 9100:
            msg = "Invalid MTU size"
            self.logger.error(msg)
            raise ValueError(msg)

        if msg is None:
            changes = self._set_l3_system_mtu(device,
                                              ip_type=ip_type,
                                              mtu_size=mtu_size)
        output['result'] = changes
        self.logger.info('closing connection to %s after configuring l3 mtu--'
                         ' all done!', self.host)
        return output

    def _set_l3_system_mtu(self, device, ip_type, mtu_size):
        self.logger.info('configuring %s mtu %i on the device', ip_type,
                         mtu_size)
        update = device.ip_mtu_update if ip_type == 'ipv4' \
            else device.ipv6_mtu_update
        try:
            set_mtu = update(mtu_size)
            if not set_mtu[0]:
                self.logger.error('Cannot set %s mtu on device due to %s', ip_type,
                                  set_mtu[1][0][self.host]
                                  ['response']['json']['output'])
            else:
                self.logger.info('Successfully set %s mtu %i on the device',
                                 ip_type, mtu_size)
        except (TypeError, AttributeError, ValueError) as e:
            self.logger.error('Cannot set %s mtu on device due to %s', ip_type,
                              e.message)
            raise ValueError(e.message)
        return set_mtu[0]
