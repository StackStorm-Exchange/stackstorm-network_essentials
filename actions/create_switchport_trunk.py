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


class CreateSwitchPort(NosDeviceAction):
    """
       Implements the logic to create switch-port on an interface on
       Switches .
       This action acheives the below functionality
           1.Check specified interface is L2 or L3,continue only if
              L2 interface.
           2.Configure switch port trunk allowed vlan add with vlan
              specified by user on the L2 interface .
           3. Configure switchport trunk vlan and ctag vlan if specified
              by the user.
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
                'successfully connected to %s to create '
                'switchport on Interface',
                self.host)
            if vlan_id == 'all':
                vlan_action = 'all'
                vlan_num = None
            else:
                vlan_action = 'add'
                vlan_num = vlan_id

            v_list, c_list = self._check_interface_presence(
                device, intf_type, intf_name, vlan_action, vlan_num, c_tag)

            if intf_type != 'port_channel':
                changes[
                    'L2_interface_check'] = \
                    self._check_requirements_L2_interface(
                        device,
                        intf_type,
                        intf_name)
            else:
                changes['L2_interface_check'] = True

            if changes['L2_interface_check']:
                changes[
                    'switchport_doesnot_exists'] = \
                    self._check_requirements_switchport_exists(
                        device, intf_type, intf_name, vlan_action, vlan_num, c_tag)
                if not changes['switchport_doesnot_exists']:
                    self.logger.info("configs are pre-existing on the device")
                if intf_type != 'port_channel' and changes[
                        'switchport_doesnot_exists']:
                    changes['disable_isl'] = self._disable_isl(device,
                                                               intf_type,
                                                               intf_name)
                    changes[
                        'disable_fabric_trunk'] = self._disable_fabric_trunk(
                        device, intf_type,
                        intf_name)
                if changes['switchport_doesnot_exists']:
                    changes[
                        'switchport_trunk_config'] = self._create_switchport(
                        device, intf_type,
                        intf_name, vlan_action, v_list, c_list)
            self.logger.info('closing connection to %s after configuring'
                             ' switch port on interface -- all done!', self.host)

        return changes

    def _check_interface_presence(self, device, intf_type, intf_name,
                                  vlan_action, vlan_id, c_tag):
        if intf_type not in device.interface.valid_int_types:
            self.logger.error('Iterface type is not valid. '
                              'Interface type must be one of %s'
                              % device.interface.valid_int_types)
            raise ValueError('Iterface type is not valid. '
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
        if vlan_action == 'add':
            vlan_list = []
            vlanlist = vlan_id.split(',')
            vlanid_list = vlan_id
            for val in vlanlist:
                temp = self.expand_vlan_range(vlan_id=val)
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
                    ctemp = self.expand_vlan_range(vlan_id=cval)
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

    def _check_requirements_L2_interface(self, device, intf_type, intf_name):
        """Fail the task if interface is an L3 interface .
        """
        try:
            version1 = 4
            version2 = 6
            get_ipv4 = device.interface.get_ip_addresses(int_type=intf_type,
                                                         name=intf_name,
                                                         version=version1)
            get_ipv6 = device.interface.get_ip_addresses(int_type=intf_type,
                                                         name=intf_name,
                                                         version=version2)
            if get_ipv4 or get_ipv6:
                self.logger.error("Interface %s %s specified i"
                                  "s an L3 interface", intf_type,
                                  intf_name)
                raise ValueError("Interface %s %s specified i"
                                 "s an L3 interface", intf_type,
                                 intf_name)
            else:
                self.logger.info("Interface is L2 interface.")
                return True

        except ValueError as e:
            self.logger.exception('Interface type or name invalid.%s'
                                  % (e.message))
            raise ValueError('Interface type or name invalid.')
        return False

    def _check_requirements_switchport_exists(self, device, intf_type,
                                              intf_name, vlan_action, vlan_id, c_tag):
        """ Fail the task if switch port exists.
        """

        try:
            return_code = device.interface.switchport(int_type=intf_type,
                                                      name=intf_name,
                                                      get='True')

            if return_code is not None:
                result = device.interface.switchport_list
                if vlan_action == 'add':
                    vlan_range = (list(self.expand_vlan_range(vlan_id)))
                for intf in result:
                    if intf['interface-name'] == intf_name:
                        if intf['mode'] == 'trunk':
                            if vlan_action == 'add':
                                if intf['vlan-id'] is not None:
                                    ret = self._check_list(vlan_range,
                                                           intf['vlan-id'])
                                    if ret:
                                        if len(ret) == len(vlan_range):
                                            return False
                                else:
                                    return True
                        else:
                            self.logger.error("Access mode is "
                                              "configured on interface,"
                                              "Pls remove and re-configure")
                            raise ValueError(
                                "Access mode is "
                                "configured on interface,"
                                "Pls remove and re-configure")
        except ValueError as e:
            self.logger.error("Fetching Switch port enable failed %s"
                              % (e.message))
            raise ValueError("Fetching Switch port enable failed")
        return True

    def _check_list(self, input_list, switch_list):
        """ Check if the input list is in switch list """
        return_list = []
        for vid in input_list:
            if str(vid) in switch_list:
                return_list.append(vid)
        return return_list

    def _create_switchport(self, device, intf_type, intf_name, vlan_action,
                           vlan_id, c_tag):
        """ Configuring Switch port trunk allowed vlan add on the
        interface with the vlan."""
        try:
            self.logger.info('Configuring Switch port trunk')
            device.interface.switchport(int_type=intf_type, name=intf_name)
            device.interface.trunk_mode(int_type=intf_type,
                                        name=intf_name, mode='trunk')
            if c_tag == []:
                device.interface.trunk_allowed_vlan(int_type=intf_type,
                                                    name=intf_name,
                                                    action=vlan_action,
                                                    vlan=vlan_id)
            else:
                for each_vl, each_ct in zip(vlan_id, c_tag):
                    device.interface.switchport_trunk_allowed_ctag(intf_type=intf_type,
                                                                   intf_name=intf_name,
                                                                   trunk_vlan_id=str(each_vl),
                                                                   trunk_ctag_id=str(each_ct))

        except ValueError as e:
            self.logger.exception("Configuring Switch port trunk failed %s"
                                  % (e.message))
            raise ValueError("Configuring Switch port trunk failed")
        return True

    def _disable_isl(self, device, intf_type, intf_name):
        """Disable ISL on the interface.
        """
        try:
            if device.os_type == 'nos':
                conf = device.interface.fabric_isl(get=True, name=intf_name,
                                                   int_type=intf_type)
                if conf is None:
                    return False
                self.logger.info(
                    "disabling isl on %s %s", intf_type, intf_name)
                device.interface.fabric_isl(enabled=False, name=intf_name,
                                            int_type=intf_type)
        except ValueError:
            self.logger.exception("disable ISL failed")
            raise ValueError("disable ISL failed")
        return True

    def _disable_fabric_trunk(self, device, intf_type, intf_name):
        """Disable ISL Fabric Trunk on the interface.
        """
        try:
            if device.os_type == 'nos':
                conf = device.interface.fabric_trunk(get=True, name=intf_name,
                                                     int_type=intf_type)
                if conf is None:
                    return False
                self.logger.info("disabling fabric trunk on %s %s", intf_type,
                                 intf_name)
                device.interface.fabric_trunk(enabled=False, name=intf_name,
                                              int_type=intf_type)
            return True
        except ValueError:
            self.logger.exception("disable fabric trunk failed")
            raise ValueError("disable fabric trunk  failed")
        return True
