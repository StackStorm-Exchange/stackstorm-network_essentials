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
import itertools

from ne_base import NosDeviceAction
from ne_base import log_exceptions


class CreateVlan(NosDeviceAction):
    """
       Implements the logic to create vlans on VDX and SLX devices.
       This action achieves the below functionality
           1.Vlan Id and description validation
           2.Check for the vlan on the Device,if not present create it
           3.No errors reported when the VLAN already exists (idempotent)
    """

    def run(self, mgmt_ip, username, password, vlan_id, vlan_desc):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(vlan_desc, vlan_id)

        return changes

    @log_exceptions
    def switch_operation(self, intf_desc, vlan_id):
        changes = {}
        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info(
                'successfully connected to %s to validate interface vlan',
                self.host)
            # Check is the user input for VLANS is correct
            vlan_list = []
            vlanlist = vlan_id.split(',')
            for val in vlanlist:
                temp = self.expand_vlan_range(vlan_id=val)
                vlan_list.append(temp)

            vlan_list = list(itertools.chain.from_iterable(vlan_list))

            valid_desc = True
            if intf_desc:
                # if description is passed we validate that the length is good.
                valid_desc = self.check_int_description(
                    intf_description=intf_desc)

            if vlan_list and valid_desc:
                changes['vlan'] = self._create_vlan(
                    device, vlan_id=vlan_list, intf_desc=intf_desc)
            else:
                raise ValueError('Input is not a valid vlan or description')

            self.logger.info('Closing connection to %s after configuring '
                             'create vlan -- all done!',
                             self.host)
        return changes

    def _create_vlan(self, device, vlan_id, intf_desc):
        output = []
        vlans = device.interface.vlans
        vlan_dict = {}
        for vlan in vlans:
            vlan_dict[vlan['vlan-id']] = vlan
        for vlan in vlan_id:
            vlan_exists = False
            if vlan in vlan_dict:
                vlan_exists = True
            result = {}
            if not vlan_exists:
                cr_vlan = device.interface.add_vlan_int(vlan)
                self.logger.info('Successfully created a VLAN %s', vlan)
                result['result'] = cr_vlan
                result['output'] = 'Successfully created a VLAN %s' % vlan
            else:
                result['result'] = 'False'
                result['output'] = 'VLAN  %s already exists on' \
                                   ' the device' % vlan
                self.logger.info('VLAN %s already exists, not created', vlan)

            if intf_desc:
                self.logger.info(
                    'Configuring VLAN description as %s', intf_desc)
                try:
                    device.interface.description(
                        int_type='vlan', name=vlan, desc=intf_desc)
                    result[
                        'description'] = 'Successfully updated VLAN ' \
                                         'description for %s' % vlan
                    self.logger.info(
                        'Successfully updated VLAN description for %s' %
                        vlan)
                except (KeyError, ValueError, AttributeError) as e:
                    self.logger.info(
                        'Configuring VLAN interface failed for %s' %
                        vlan)
                    raise ValueError(
                        'Configuring VLAN interface failed', e.message)
            else:
                self.logger.debug('Skipping to update Interface description,'
                                  ' as no info provided')
            output.append(result)
        return output
