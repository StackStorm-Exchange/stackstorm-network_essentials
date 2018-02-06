import sys
from ne_base import NosDeviceAction
from ne_base import log_exceptions
import re


class set_l3_system_mtu(NosDeviceAction):

    def run(self, mgmt_ip, username, password, mtu_size, afi):
        """Run helper methods to set system L3 MTU on.
        """
        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as e:
            self.logger.error(e.message)
            sys.exit(-1)
        output = self.switch_operation(afi, mtu_size)
        return output

    @log_exceptions
    def switch_operation(self, afi, mtu_size):
        output = {}
        changes = []
        ip_version = int(re.search(r'ipv([\d.]+)', afi).group(1))
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'successfully connected to %s to set system IP mtu',
                self.host)

            changes = self._set_l3_system_mtu(device,
                                              mtu_size=mtu_size,
                                              ip_version=ip_version)
            output['result'] = changes
            self.logger.info('closing connection to %s after '
                             'configuring system IP mtu --'
                             ' all done!', self.host)
        return output

    def _set_l3_system_mtu(self, device, mtu_size, ip_version):
        self.logger.info('configuring mtu_size %i on the device',
                         mtu_size)

        try:
            device.system.system_ip_mtu(
                mtu=mtu_size, version=ip_version)

            self.logger.info('Successfully  set system IP mtu_size %i on '
                             'the device',
                             mtu_size)
        except (TypeError, AttributeError, ValueError) as e:
            self.logger.error('Cannot set system IP mtu on device due to %s',
                              e.message)
            raise ValueError(e.message)
        return True
