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
import itertools
import sys


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
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'successfully connected to %s to Remove '
                'switchport trunk allowed vlan on the Interface',
                self.host)

            if device.os_type != 'nos' and c_tag is not None:
                self.logger.error('c_tag mapping under switchport is not '
                                  'supported on this platform')
                sys.exit(-1)

            v_list, c_list = self._check_interface_presence(
                device, intf_type, intf_name, vlan_id, c_tag)

            changes['switchport_doesnot_exists'] = \
                self._check_requirements_switchport_exists(device, intf_type,
                                                           intf_name)
            if changes['switchport_doesnot_exists']:
                changes['switchport_trunk_config'] = self._remove_switchport(device, intf_type,
                                                                             intf_name,
                                                                             vlan_id=v_list,
                                                                             c_tag=c_list)
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
        c_tag_list = []
        vlanid_list = []
        vlan_list = []
        vlanlist = vlan_id.split(',')
        vlanid_list = vlan_id
        for val in vlanlist:
            temp = self.expand_vlan_range(vlan_id=val, device=device)
            if temp is None:
                raise ValueError('Reserved/Control Vlans passed in args `vlan_id`')
            vlan_list.append(temp)

        vlan_list = list(itertools.chain.from_iterable(vlan_list))

        for vf in vlan_list:
            if c_tag is not None:
                vlanid_list = vlan_list
                if int(vf) not in xrange(4096, 8192):
                    self.logger.error('Vlans in vlan_id %s must be in'
                                      ' range(4096,8191)', vlan_id)
                    raise ValueError('Vlans in vlan_id must be in range(4096,8191)')
            else:
                if int(vf) not in xrange(1, 4091):
                    self.logger.error('Vlans in vlan_id %s must be in range(1,4090)',
                                      vlan_id)
                    raise ValueError('Vlans in vlan_id must be in range(1,4090)')

        if c_tag is not None:
            ctag_list = c_tag.split(',')
            for cval in ctag_list:
                ctemp = self.expand_vlan_range(vlan_id=cval, device=device)
                c_tag_list.append(ctemp)
            c_tag_list = list(itertools.chain.from_iterable(c_tag_list))
            for ctag in c_tag_list:
                if int(ctag) not in xrange(1, 4091):
                    self.logger.error('Vlans in c_tag %s must be in range(1,4090)',
                                      c_tag)
                    raise ValueError('Vlans in c_tag must be in range(1,4090)')
            if len(vlanid_list) != len(c_tag_list):
                self.logger.error('Both vlan_id %s & c_tag %s must be either'
                                  ' a single value or'
                                  ' list of equal length', vlan_id, c_tag)
                raise ValueError('Unsupported vlan_id & c_tag combination passed')

        return vlanid_list, c_tag_list

    def _check_requirements_switchport_exists(self, device, intf_type, intf_name):
        """ Fail the task if switch port exists.
        """

        # MLX doesnt have switchport concept, so just return true to be
        # compatible with existing code
        if device.os_type == "NI":
            return True

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
            if c_tag == []:
                device.interface.trunk_allowed_vlan(int_type=intf_type,
                                                    name=intf_name,
                                                    action='remove',
                                                    vlan=vlan_id)
            else:
                for each_vl, each_ct in zip(vlan_id, c_tag):
                    device.interface.switchport_trunk_allowed_ctag(delete=True,
                                                           intf_type=intf_type,
                                                           intf_name=intf_name,
                                                           trunk_vlan_id=str(each_vl),
                                                           trunk_ctag_id=str(each_ct))

        except ValueError as e:
            self.logger.exception("Removing Switch port trunk vlan failed %s"
                                  % (e.message))
            raise ValueError("Removing Switch port trunk vlan failed")
        return True
