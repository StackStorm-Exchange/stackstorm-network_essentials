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

from ne_base import NosDeviceAction


class FindMAC(NosDeviceAction):
    """
       Implements the logic to find MACs on an interface on VDX or SLX Devices .
    """

    def run(self, mgmt_ip, username, password, macs):
        """Run helper methods to implement the desired state.
        """

        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as e:
            self.logger.error(e.message)
            sys.exit(-1)
        results = []
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info('successfully connected to %s to find mac address', self.host)

            self._check_requirements(macs)
            results = self._find_mac_addresses(device, macs)
            self.logger.info('Closing connection to %s after searching MACs -- all done!',
                         self.host)
        return results

    def _check_requirements(self, macs):
        for mac in macs:
            if not self.is_valid_mac(mac):
                raise ValueError('Not a valid MAC %s to find', mac)

    def _find_mac_addresses(self, device, macs):

        """ Find MACs found on interfaces in a VCS."""
        try:
            mac_table = device.services.mac_table
        except Exception as e:
            raise ValueError(e.message)
        results = []
        mac_list = []
        for mac in macs:
            mac_list.append(self.mac_converter(mac))
        for each in mac_list:
            found = False
            for mac in mac_table:
                if mac['mac_address'] == each:
                    output = {}
                    found = True
                    self.logger.info('mac_address %s found', each)
                    for key, value in mac.iteritems():
                        output[key] = value
                    if output['interface_type'] == 'port-channel':
                        output['member_ports'] = []
                        port_channel_num = output['interface_name']
                        port_channels = device.interface.port_channels
                        members = next((pc['interfaces'] for pc in port_channels
                                      if pc['aggregator_id'] == port_channel_num), None)
                        for member in members:
                            output['member-ports'].\
                                append(member['interface-type'] + ' ' + member['interface-name'])
                    results.append(output)
            if found is False:
                self.logger.info('mac-address %s not found', each)
        return results
