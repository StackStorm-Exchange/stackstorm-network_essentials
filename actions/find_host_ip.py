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


class FindHostIP(NosDeviceAction):
    """
       Implements the logic to find IPs on an interface on VDX Switches .
    """

    def run(self, mgmt_ip, username, password, ip_address):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        results = {}

        with self.mgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s to find IP on a VCS', self.host)
            self._check_requirements(ip_address)
            results = self._find_ip_addresses(device, ip_address)
            self.logger.info('closing connection to %s after searching for IP address -- all done!',
                             self.host)
        return results

    def _check_requirements(self, ip_address):
        """ Verify if the port channel already exists """
        if not self.is_valid_ip(ip_address):
            raise ValueError('Not a valid IP address %s to find', ip_address)

    def _find_ip_addresses(self, device, ip):
        """ Find IPs found on interfaces in a VCS."""
        # For now its ony IPv4 address and hence this check. Eventually it will also be IPv6 and VRF
        arp_table = device.services.arp
        results = [x for x in arp_table if x['ip-address'] == ip]
        return results
