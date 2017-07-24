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
import re


class RemoveSwitchPort(NosDeviceAction):
    """
       Implements the logic to remove switchport vlan from an interface
       This action acheives the below functionality
           1. Check if interface exists
           2. Remove switchport trunk allowed vlan on the interface
    """

    def run(self, mgmt_ip, username, password, intf_type, intf_name, vlan_id, c_tag):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(intf_name, intf_type, vlan_id, c_tag)
        return changes

    @log_exceptions
    def switch_operation(self, intf_name, intf_type, vlan_id, c_tag):
        changes = {}
        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info(
                'successfully connected to %s to Remove '
                'switchport trunk allowed vlan on the Interface',
                self.host)

            changes['Interface_Present'] = self._check_interface_presence(
                device, intf_type, intf_name, vlan_id, c_tag)

            changes['switchport_doesnot_exists'] = \
                self._check_requirements_switchport_exists(device, intf_type,
                                                           intf_name)
            if changes['switchport_doesnot_exists']:
                changes['switchport_trunk_config'] = self._remove_switchport(device, intf_type,
                                                                             intf_name, vlan_id,
                                                                             c_tag)
            self.logger.info('closing connection to %s after Removing the'
                             ' switch port trunk allowed vlan on interface -- all done!', self.host)

        return changes

    def _check_interface_presence(self, device, intf_type, intf_name,
                                  vlan_id, c_tag):
        if intf_type not in device.interface.valid_int_types:
            self.logger.error('Interface type is not valid. '
                              'Interface type must be one of %s'
                              % device.interface.valid_int_types)
            raise ValueError('Interface type is not valid. '
                             'Interface type must be one of %s'
                             % device.interface.valid_int_types)

        if not self.validate_interface(intf_type, intf_name):
            raise ValueError('Interface %s is not valid' % (intf_name))

        if not device.interface.interface_exists(int_type=intf_type,
                                                 name=intf_name):
            self.logger.error('Interface %s %s not present on the Device'
                              % (intf_type, intf_name))
            raise ValueError('Interface %s %s not present on the Device'
                             % (intf_type, intf_name))
        if c_tag is not None:
            ctag_pattern = r"^(\d+)$"
            if not re.match(ctag_pattern, c_tag):
                self.logger.error('Invalid c_tag %s format, '
                                  'c_tag range is not support', c_tag)
                raise ValueError('Invalid c_tag %s format' % (c_tag))
            if int(c_tag) not in range(1, 4091):
                if int(vlan_id) not in range(4096, 8192):
                    self.logger.error('c_tag vlan %s must be in range(1,4090) &'
                                      'vlan_id %s must be in range(4096,8191)',
                                      c_tag, vlan_id)
                    raise ValueError('c_tag vlan is not in range(1,4090) &'
                                     ' vlan_id is not in range(4096,8191)')
                self.logger.error('c_tag vlan %s must be in range(1,4090)' % (c_tag))
                raise ValueError('c_tag vlan %s must be in range(1,4090)' % (c_tag))
            vlan_list = vlan_id.split(',') + [c_tag]
        else:
            vlan_list = vlan_id.split(',')
        for vlan in vlan_list:
            vl_list = self.expand_vlan_range(vlan)
            if vl_list is not None:
                vl_list = list(vl_list)
                if c_tag is None and\
                        [vl for vl in vl_list if vl not in range(1, 4091)] != []:
                    self.logger.error('Invalid vlan_id range, '
                                      'vlan_id %s is not in range(1,4090)', vlan_id)
                    raise ValueError('Invalid vlan_id range, '
                                     'vlan_id %s is not in range(1,4090)' % (vlan_id))
                for vlan_id in vl_list:
                    if not device.interface.get_vlan_int(vlan_id=vlan_id):
                        self.logger.error('Vlan %s not present on the Device' % (vlan_id))
                        raise ValueError('Vlan %s not present on the Device' % (vlan_id))
            else:
                self.logger.error('vlan_id %s contains non user vlans' % (vlan_id))
                raise ValueError('vlan_id %s contains non user vlans' % (vlan_id))

        return True

    def _check_requirements_switchport_exists(self, device, intf_type, intf_name):
        """ Fail the task if switch port exists.
        """

        return_code = device.interface.switchport(int_type=intf_type,
                                                  name=intf_name,
                                                  get='True')
        if return_code is None:
            self.logger.error('switchport is not present on'
                              ' the interface %s', intf_name)
            raise ValueError('switchport is not present on'
                             ' the interface %s' % intf_name)
        return True

    def _remove_switchport(self, device, intf_type, intf_name,
                           vlan_id, c_tag):
        """ Removing Switch port trunk allowed vlan on the
        interface with the vlan."""

        try:
            self.logger.info('Removing Switch port trunk allowed vlan %s', vlan_id)
            if c_tag is None:
                device.interface.trunk_allowed_vlan(int_type=intf_type,
                                                    name=intf_name,
                                                    action='remove',
                                                    vlan=vlan_id)
            else:
                device.interface.switchport_trunk_allowed_ctag(delete=True,
                                                           intf_type=intf_type,
                                                           intf_name=intf_name,
                                                           trunk_vlan_id=vlan_id,
                                                           trunk_ctag_id=c_tag)

        except ValueError as e:
            self.logger.exception("Removing Switch port trunk vlan failed %s"
                                  % (e.message))
            raise ValueError("Removing Switch port trunk vlan failed")
        return True
