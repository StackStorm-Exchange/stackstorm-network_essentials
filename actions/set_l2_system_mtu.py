from ne_base import NosDeviceAction
from ne_base import log_exceptions
import sys


class set_l2_system_mtu(NosDeviceAction):

    def run(self, mgmt_ip, username, password, mtu_size):
        """Run helper methods to set system L2 MTU on.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        output = self.switch_operation(mtu_size)
        return output

    @log_exceptions
    def switch_operation(self, mtu_size):
        output = {}
        changes = []
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'successfully connected to %s to set system mtu',
                self.host)

            changes = self._set_l2_system_mtu(device,
                                              mtu_size=mtu_size)
            output['result'] = changes
            self.logger.info('closing connection to %s after configuring '
                             'L2 mtu --'
                             ' all done!', self.host)
        return output

    def _set_l2_system_mtu(self, device, mtu_size):

        self.logger.info('Configuring mtu_size %d on the device',
                         mtu_size)

        try:
            device.system.system_l2_mtu(mtu=mtu_size)
            self.logger.info('Successfully set mtu_size %d on the device',
                             mtu_size)

        except (TypeError, AttributeError, ValueError) as e:
            self.logger.error('Cannot set L2 mtu on device due to %s',
                              e.message)
            sys.exit(-1)
        return True
