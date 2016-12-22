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
       Implements the logic to find MACs on an interface on VDX or SLX Devices .
    """

    def run(self, mgmt_ip, user, passwd, macs):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=user, passwd=passwd)
        results = []
        try:
            device = self.asset(ip_addr=self.host, auth=self.auth)
            self.logger.info('successfully connected to %s to enable interface', self.host)
        except AttributeError as e:
            self.logger.info('Failed to connect to %s due to %s', self.host, e.message)
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
            mac_table = device.get_mac_address_table_rpc(None)
        except Exception as e:
            raise ValueError(e.message)
        mac_list = []
        results = []
        for mac in macs:
            mac_list.append(self.mac_converter(mac))
        mac_result = mac_table[1][0][self.host]['response']['json']['output']['mac-address-table']
        if type(mac_result) == dict:
            mac_result = [mac_result, ]
        for each in mac_list:
            found = False
            for mac in mac_result:
                if mac['mac-address'] == each:
                    output = {}
                    found = True
                    self.logger.info('mac-address %s found', each)
                    for key, value in mac.iteritems():
                        output[key] = value
                    if output['forwarding-interface']['interface-type'].startswith('port-channel'):
                        output['member-ports'] = []
                        port_channel_num = int(output['forwarding-interface']['interface-name'])
                        members = self._get_port_channel_members(device, port_channel_num)
                        for member in members:
                            output['member-ports'].\
                                append(member['interface-type'] + ' ' + member['interface-name'])
                    results.append(output)
            if found is False:
                self.logger.info('mac-address %s not found', each)
        return results
