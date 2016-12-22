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


class CreateVlan(NosDeviceAction):
    """
       Implements the logic to create vlans on VDX and SLX devices.
       This action achieves the below functionality
           1.Vlan Id and description validation
           2.Check for the vlan on the Device,if not present create it
    """

    def run(self, mgmt_ip, username, password, vlan_id, intf_desc):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}

        try:
            device = self.asset(ip_addr=self.host, auth=self.auth)
            self.logger.info('successfully connected to %s to enable interface', self.host)
        except AttributeError as e:
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

        # Check is the user input for VLANS is correct
        vlan_list = self.expand_vlan_range(vlan_id=vlan_id)

        valid_desc = True
        if intf_desc:
            # if description is passed we validate that the length is good.
            valid_desc = self.check_int_description(intf_description=intf_desc)

        if vlan_list and valid_desc:
            changes['vlan'] = self._create_vlan(device, vlan_id=vlan_list, intf_desc=intf_desc)
        else:
            raise ValueError('Input is not a valid vlan or description')

        self.logger.info('Closing connection to %s after configuring create vlan -- all done!',
                         self.host)

        return changes

    def _create_vlan(self, device, vlan_id, intf_desc):
        result = {}

        for vlan in vlan_id:
            check_vlan = device.vlan_get(vlan)

            if str(check_vlan[0]) == 'False':
                cr_vlan = device.vlan_create(vlan)
                self.logger.info('Successfully created a VLAN %s', vlan)
                result['result'] = cr_vlan[0]
                result['output'] = cr_vlan[1][0][self.host]['response']['json']['output']
            else:
                result['result'] = 'False'
                result['output'] = 'VLAN already exists on the device'
                self.logger.info('VLAN %s already exists, not created', vlan)

            if intf_desc:
                self.logger.info('Configuring VLAN description as %s', intf_desc)
                try:
                    desc = device.vlan_update(vlan=str(vlan), description=str(intf_desc))
                    if 'False' in str(desc[0]):
                        self.logger.info('Cannot update vlan interface description because %s',
                                         desc[1][0][self.host]['response']['json']['output'])
                    elif 'True' in str(desc[0]):
                        self.logger.info('Successfully updated VLAN description')
                except self.ValueError as vr:
                    self.logger.info('Configuring VLAN interface failed')
                    raise ValueError('Configuring VLAN interface failed', vr.message)
            else:
                self.logger.debug('Skipping to update Interface description,'
                                  ' as no info provided')
        return result
