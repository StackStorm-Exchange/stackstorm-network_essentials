# Copyright 2016 Brocade Communications Systems, Inc.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys

from ipaddress import ip_interface

from ne_base import NosDeviceAction
from ne_base import log_exceptions


class ConfigVcsVirtualIp(NosDeviceAction):
    """
       Implements the logic to configure Managemnt virtual IP on VDX switches.
       This action acheives the below functionality
           1.IPv4 and IPv6 address as can be configured
           2.Check for the management virtual IP on the Device,if not present
           configure it
    """

    def run(self, mgmt_ip, username, password, mgmt_vip):
        """Run helper methods to implement the desired state.
        """
        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as e:
            self.logger.error(e.message)
            sys.exit(-1)
        changes = self.switch_operation(mgmt_vip)

        return changes

    @log_exceptions
    def switch_operation(self, mgmt_vip):
        changes = {}
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'successfully connected to %s to configure VCS virtual IP',
                self.host)
            if not device.suports_rbridge:
                self.logger.error('This operation is supported only on NOS.')
                raise ValueError('This operation is supported only on NOS.')
            changes['vip'] = self._configure_vip(device, vip=mgmt_vip)
            self.logger.info(
                'closing connection to %s after configuring '
                'virtual IP -- all done!',
                self.host)
        return changes

    def _configure_vip(self, device, vip):
        """Configure vcs virtual ip under global mode.
        """

        ipaddress = ip_interface(unicode(vip))
        vips = device.vcs.vcs_vip(get=True)

        if ipaddress.version == 4:
            conf = vips['ipv4_vip']

        if ipaddress.version == 6:
            conf = vips['ipv6_vip']

        if conf is not None:
            self.logger.info(
                "Management virtual IPv%s address is already configured",
                ipaddress.version)
        else:
            self.logger.info(
                "Configuring Management virtual IPv%s address %s on %s",
                ipaddress.version, vip, self.host)
            device.vcs.vcs_vip(vip=vip)

        return True
