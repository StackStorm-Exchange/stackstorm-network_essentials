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


class FindMAC(NosDeviceAction):
    """
       Implements the logic to find MACs on an interface on VDX Switches .
    """

    def run(self, mgmt_ip, username, password, macs):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        results = {}

        with self.mgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s to find MACs on a VCS', self.host)
            self._check_requirements(macs)
            results = self._find_mac_addresses(device, macs)
            self.logger.info('closing connection to %s after searching MACs -- all done!',
                             self.host)

        return results

    def _check_requirements(self, macs):
        """ Verify if the port channel already exists """
        for mac in macs:
            if not self.is_valid_mac(mac):
                raise ValueError('Not a valid MAC %s to find', mac)

    def _find_mac_addresses(self, device, macs):
        """ Find MACs found on interfaces in a VCS."""
        mac_table = device.mac_table
        port_channels = device.interface.port_channels
        mac_list = []
        for mac in macs:
            mac_list.append(self.mac_converter(mac))
        results = [x for x in mac_table if x['mac_address'] in mac_list]
        for result in results:
            result['member-ports'] = []
            if result['interface'].startswith('port-channel'):
                for po in port_channels:
                    if result['interface'] == ('port-channel' + po['aggregator_id']):
                        for interface in po['interfaces']:
                            result['member-ports'].append(interface['interface-name'])
        return results
