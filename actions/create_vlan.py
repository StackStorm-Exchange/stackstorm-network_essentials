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
       Implements the logic to create vlans on VDX switches.
       This action acheives the below functionality
           1.Vlan Id validation
           2.Check for the vlan on the Device,if not present create it
    """

    virtual_fabric = "Fabric is not enabled to support Virtual Fabric configuration"

    def run(self, mgmt_ip, username, password, vlan_id, intf_desc):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}

        with self.mgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s to create vlan', self.host)
            # Check is the user input for VLANS is correct
            vlan_list = self.expand_vlan_range(vlan_id=vlan_id)
            # Check if the description is valid
            valid_desc = True
            if intf_desc:
                # if description is passed we validate that the length is good.
                valid_desc = self.check_int_description(intf_description=intf_desc)
            if vlan_list and valid_desc:
                changes['vlan'] = self._create_vlan(device, vlan_id=vlan_list, intf_desc=intf_desc)
            else:
                raise ValueError('Input is not a valid vlan or description')
            self.logger.info('closing connection to %s after configuring create vlan -- all done!',
                             self.host)
        return changes

    def _create_vlan(self, device, vlan_id, intf_desc):
        """Configure vlan under global mode.
        """

        vlan_len = len(vlan_id)
        sysvlans = device.interface.vlans
        is_vlan_interface_present = False

        """ The below code is to verify the given vlan is already present in VDX switch
        """
        vlan_list = []
        for vlan in vlan_id:
            for svlan in sysvlans:
                temp_vlan = int(svlan['vlan-id'])
                if temp_vlan == vlan:
                    is_vlan_interface_present = True
                    vlan_list.append(vlan)
                    self.logger.info('vlan %s already present on %s', vlan, self.host)
                    if intf_desc:
                        device.interface.description(int_type="vlan", name=vlan,
                                                     desc=intf_desc)
                    else:
                        self.logger.debug('Skipping description configuration')
                    if vlan_len == 1:
                        break

            """ The below code is for creating single vlan.
            """
            if not is_vlan_interface_present and vlan_len == 1:
                self.logger.info('configuring vlan %s on %s', vlan, self.host)
                error = device.interface.add_vlan_int(str(vlan))
                if intf_desc:
                    device.interface.description(int_type="vlan", name=vlan,
                                                 desc=intf_desc)
                else:
                    self.logger.debug('Skipping description configuration')
                if not error:
                    msg = 'Fabric is not enabled to support Virtual Fabric configuration \
                           on %s' % self.host
                    raise ValueError(msg)

        """ The below code is for creating more than one vlan.
        """
        if vlan_len > 1:
            vid_list = [x for x in vlan_id if x not in vlan_list]
            for vlan in vid_list:
                self.logger.info('configuring vlan %s on %s', vlan, self.host)
                error = device.interface.add_vlan_int(str(vlan))
                if intf_desc:
                    device.interface.description(int_type="vlan", name=vlan,
                                                 desc=intf_desc)
                else:
                    self.logger.debug('Skipping description configuration')

                if not error:
                    msg = 'Fabric is not enabled to support Virtual Fabric configuration \
                           on %s' % self.host
                    raise ValueError(msg)

        return True
