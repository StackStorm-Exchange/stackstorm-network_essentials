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

from ne_base import NosDeviceAction
from ipaddress import ip_interface


class ConfigVcsVirtualIp(NosDeviceAction):
    """
       Implements the logic to configure Managemnt virtual IP on VDX switches.
       This action acheives the below functionality
           1.IPv4 and IPv6 address as can be configured
           2.Check for the management virtual IP on the Device,if not present configure it
    """

    def run(self, principal_mgmt_ip, username, password, mgmt_vip):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=principal_mgmt_ip, user=username, passwd=password)
        changes = {}

        with self.mgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s to configure VCS virtual IP', self.host)
            changes['vip'] = self._configure_vip(device, vip=mgmt_vip)
            self.logger.info('closing connection to %s after configuring virtual IP -- all done!',
                             self.host)
        return changes

    def _configure_vip(self, device, vip):
        """Configure vcs virtual ip under global mode.
        """

        ipaddress = ip_interface(unicode(vip))
        vips = device.vcs.vcs_vip(get=True)

        if ipaddress.version == 4:
            ipv4_config = vips['ipv4_vip']
            conf = ipv4_config.data.find('.//{*}address')
        if ipaddress.version == 6:
            ipv6_config = vips['ipv6_vip']
            conf = ipv6_config.data.find('.//{*}ipv6address')

        if conf is not None:
            self.logger.info("Managemnt virtual IPv%s address is already configured",
                             ipaddress.version)
        else:
            self.logger.info("Configuring Managemnt virtual IPv%s address %s on %s",
                             ipaddress.version, vip, self.host)
            device.vcs.vcs_vip(vip=vip)

        return True
