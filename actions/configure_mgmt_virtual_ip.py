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
       Implements the logic to configure Management virtual IP on VDX switches.
       This action acheives the below functionality
           1.IPv4 and IPv6 address as can be configured
           2.Check for the management virtual IP on the Device,if not present configure it
    """

    def run(self, mgmt_ip, username, password, mgmt_vip):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}
        try:
            device = self.asset(ip_addr=self.host, auth=self.auth)
            self.logger.info('successfully connected to %s to configure VCS virtual IP', self.host)
        except AttributeError as e:
            self.logger.error('Failed to connect %s due to %s', self.host, e.message)
            raise ValueError('Failed to connect %s due to %s', self.host, e.message)
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
            self.logger.error("Failed to get a REST response while logging in to %s due to %s",
                              self.host, rierr.message)
            raise ValueError("Failed to get a REST response while logging in to %s due to %s",
                             self.host, rierr.message)

        changes['vip'] = self._configure_vip(device, vip=mgmt_vip)
        self.logger.info('closing connection to %s after configuring virtual IP -- all done!',
                         self.host)
        return changes

    def _configure_vip(self, device, vip):
        """Configure vcs virtual ip under global mode.
        """
        ip_address = ip_interface(unicode(vip))
        if self._validate_ip_(unicode(ip_address.ip)):
            ip_version = 4
            get = device.vcs_virtual_ip_address_get()
            config_mgmt_vip = device.vcs_virtual_ip_address_create
        elif self._validate_ipv6_(unicode(ip_address.ip)):
            ip_version = 6
            get = device.vcs_virtual_ipv6_address_get()
            config_mgmt_vip = device.vcs_virtual_ipv6_address_create
        else:
            self.logger.error("Invalid IP address %s", vip)
            return False

        if get[0]:
            output = get[1][0][self.host]['response']['json']['output']
            if 'address' in output:
                self.logger.error("Management virtual IPv%s address is already "
                                  "configured with address %s",
                                  ip_version, output['address']['address'])
                return False
        else:
            self.logger.error("Cannot get VCS virtual IP from device %s", self.host)
            return False

        self.logger.info("Configuring Management virtual IPv%s address %s on %s",
                         ip_version, vip, self.host)

        try:
            create = config_mgmt_vip(address=vip)
            if not create[0]:
                self.logger.error('Cannot configure management virtual IP due to %s',
                                  create[1][0][self.host]['response']['json']['output'])
                return False
            else:
                self.logger.info('Successfully configured management virtual IPv%s '
                                 'address %s in %s', ip_version, vip, self.host)
        except (KeyError, ValueError, AttributeError) as e:
            raise ValueError(e.message)

        return True
