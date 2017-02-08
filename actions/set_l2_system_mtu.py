from ne_base import NosDeviceAction


class set_l2_mtu(NosDeviceAction):
    def run(self, mgmt_ip, username, password, mtu_size):
        """Run helper methods to set system L2 MTU on.
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
        if not 1522 <= mtu_size <= 9216:
            msg = "Invalid MTU size"
            self.logger.error(msg)
            raise ValueError(msg)

        if msg is None:
            changes = self._set_l2_system_mtu(device,
                                              mtu_size=mtu_size)
        output['result'] = changes
        self.logger.info('closing connection to %s after configuring L2 mtu --'
                         ' all done!', self.host)
        return output

    def _set_l2_system_mtu(self, device, mtu_size):
        self.logger.info('configuring mtu_size %i on the device',
                         mtu_size)
        try:
            set_mtu = device.mtu_update(global_l2_mtu=mtu_size)
            if not set_mtu[0]:
                self.logger.error('Cannot set L2 mtu on device due to %s',
                                  set_mtu[1][0][self.host]
                                  ['response']['json']['output'])
            else:
                self.logger.info('Successfully  set  mtu_size %i on the device',
                                 mtu_size)
        except (TypeError, AttributeError, ValueError) as e:
            self.logger.error('Cannot set L2 mtu on device due to %s',
                              e.message)
            raise ValueError(e.message)
        return set_mtu[0]
