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
from ne_base import log_exceptions
import sys


class CreateVlan(NosDeviceAction):
    """
       Implements the logic to create vlans on VDX and SLX devices.
       This action achieves the below functionality
           1.Create a Vlan Id and description
    """

    def run(self, mgmt_ip, username, password, vlan_id, vlan_desc):
        """Run helper methods to implement the desired state.
        """

        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as e:
            self.logger.error(e.message)
            sys.exit(-1)
        changes = self.switch_operation(vlan_desc, vlan_id)

        return changes

    @log_exceptions
    def switch_operation(self, intf_desc, vlan_id):
        changes = {}
        with self.pmgr(conn=self.conn,
                       auth_snmp=self.auth_snmp, connection_type='NETCONF') as device:
            self.logger.info(
                'Successfully connected to %s to create interface vlans',
                self.host)
            # Check is the user input for VLANS is correct
            try:
                vlan_list = self.get_vlan_list(vlan_id, device)
            except Exception as e:
                error_msg = str(e.message)
                self.logger.error("Error creating VLAN %s", error_msg)
                sys.exit(-1)

            valid_desc = True
            if intf_desc:
                valid_desc = self.check_int_description(intf_description=intf_desc)
            if not valid_desc:
                raise ValueError('Unsupported `vlan_desc` value passed', intf_desc)

            changes['vlan'] = self._create_vlan(device, vlan_list, intf_desc, vlan_id)

            self.logger.info('Closing connection to %s after '
                             'creating vlan -- all done!',
                             self.host)
        return changes

    def _create_vlan(self, device, vlan_list, intf_desc, vlan_id):

        try:
            self.logger.info('Creating Vlans')
            device.interface.add_vlan_int(vlan_id_list=vlan_list, desc=intf_desc)
        except (KeyError, ValueError) as e:
            self.logger.error('VLAN creation failed due to %s' % (e.message))
            sys.exit(-1)

        return True
