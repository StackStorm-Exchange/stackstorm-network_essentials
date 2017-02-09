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


class CreateSwitchPort(NosDeviceAction):
    """
       Implements the logic to create switch-port on an interface on VDX Switches .
       This action acheives the below functionality
           1.Check specified interface is L2 or L3,continue only if L2 interface.
           2.Configure switch port access vlan with vlan specified by user on the L2 interface .
    """

    def run(self, mgmt_ip, username, password, intf_type, intf_name, vlan_id):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}
        device = self.get_device()
        self.logger.info('successfully connected to %s to create switchport on Interface',
                         self.host)
        changes['L2_interface_check'] = self._check_requirements_L2_interface(device, intf_type,
                                                                              intf_name)
        changes['switchport_doesnt_exists'] = \
            self._check_requirements_switchport_exists(device, intf_type, intf_name, vlan_id)
        if changes['switchport_doesnt_exists']:
            changes['disable_isl'] = self._disable_isl(device, intf_type, intf_name)
            changes['disable_fabric_trunk'] = self._disable_fabric_trunk(device, intf_type,
                                                                         intf_name)
            changes['switchport_access_config'] = self._create_switchport(device, intf_type,
                                                                          intf_name, vlan_id)
        else:
            self.logger.info('configs are pre-existing on the device')
        self.logger.info(
            'closing connection to %s after configuring switch port on interface -- all done!',
            self.host)
        return changes

    def _check_requirements_L2_interface(self, device, intf_type, intf_name):
        """Fail the task if interface is an L3 interface .
        """

        version1 = 4
        version2 = 6
        intf_state = self._get_interface_admin_state(device, intf_type=intf_type,
                                                     intf_name=intf_name)
        if intf_state:
            get_ipv4 = self._get_interface_address(device, intf_type=intf_type,
                                                   intf_name=intf_name, ip_version=version1)
            get_ipv6 = self._get_interface_address(device, intf_type=intf_type,
                                                   intf_name=intf_name, ip_version=version2)
            if get_ipv4 or get_ipv6:
                self.logger.warning("Interface %s %s specified is an L3 interface", intf_type,
                                    intf_name)
                return False
            else:
                self.logger.info("Interface is L2 interface.")
                return True

        else:
            self.logger.info("interface type or name invalid.")
            return False

    def _check_requirements_switchport_exists(self, device, intf_type, intf_name, vlan_id):
        """ Fail the task if switch port exists.
        """
        try:
            check_switchport = self._get_interface_switchport(device, intf_type, intf_name)
            if check_switchport[0]:
                result = self._get_switchport(device)
                for intf in result:
                    vlanid = None
                    if intf['interface-name'] == intf_name:
                        if intf['mode'] == 'access':
                            if intf['active-vlans'] is not None:
                                vlanid = intf['active-vlans']['vlanid']
                                if not isinstance(vlanid, list):
                                    vlanid = [vlanid, ]
                            if vlanid is not None:
                                for vid in intf['vlan-id']:
                                    if int(vid) == vlan_id:
                                        return False
                            else:
                                return True
                        else:
                            self.logger.info("Switchport trunk already on Interface,\
                              Pls removed and re - configure")
                            return False
        except (ValueError, IndexError, KeyError):
            self.logger.info("Fetching Switch port enable failed")
            return False
        return True

    def _check_list(self, input_list, switch_list):
        """ Check if the input list is in switch list """
        return_list = []
        for vid in input_list:
            if str(vid) in switch_list:
                return_list.append(vid)
        return return_list

    def _create_switchport(self, device, intf_type, intf_name, vlan_id):
        """Configuring Switch port access vlan on the interface with vlan"""
        try:
            switchport_create = \
                eval("device.interface_{}_switchport_update".format(intf_type))
            update_1 = switchport_create(intf_name)
            if update_1[0]:
                self.logger.info('Configuring interface %s %s mode to switchport'
                                 ' is done', intf_type, intf_name)
            else:
                self.logger.error('Switchport creation failed'
                                  ' due to %s',
                                  update_1[1][0][self.host]['response']['json']['output'])
                return False

            access_mode_update = \
                eval("device.interface_{}_switchport_mode_update".format(intf_type))
            update_2 = access_mode_update(intf_name, vlan_mode='access')
            if update_2[0]:
                self.logger.info('Configuring switchport mode to access'
                                 ' is done')
            else:
                self.logger.error('Switchport mode update failed'
                                  ' due to %s',
                                  update_2[1][0][self.host]['response']['json']['output'])
                return False

            return True
        except (ValueError, AttributeError):
            self.logger.info("Configuring Switch port access failed")
            return False

    def _disable_isl(self, device, intf_type, intf_name):

        """Disable ISL on the interface.
                """
        self.logger.info('disabling fabric ISL settings on the interface ')
        if intf_type == 'ethernet':
            update = device.interface_ethernet_fabric_isl_update
        elif intf_type == 'gigabitethernet':
            update = device.interface_gigabitethernet_fabric_isl_update
        elif intf_type == 'tengigabitethernet':
            update = device.interface_tengigabitethernet_fabric_isl_update
        elif intf_type == 'fortygigabitethernet':
            update = device.interface_fortygigabitethernet_fabric_isl_update
        elif intf_type == 'hundredgigabitethernet':
            update = device.interface_hundredgigabitethernet_fabric_isl_update
        else:
            self.logger.error('intf_type %s is not supported',
                              intf_type)
            return False

        try:
            for intf in intf_name:
                self.logger.info("disabling fabric ISL "
                                 "settings on %s %s", intf_type, intf)
                conf_intf = update(intf, fabric_isl_enable=False)
                if conf_intf[0] == 'True':
                    self.logger.info('disabling fabric trunk on %s %s is done', intf_type, intf)

                elif conf_intf[0] == 'False':
                    self.logger.error('disabling fabric trunk on %s %s failed due to %s',
                                      intf_type,
                                      intf,
                                      conf_intf[1][0][self.host]
                                      ['response']['json']['output'])
        except (KeyError, ValueError, AttributeError):
            self.logger.error('Invalid Input values while disabling fabric trunk')
            return False
        return True

    def _disable_fabric_trunk(self, device, intf_type, intf_name):

        """Disable fabric trunk on the interface."""

        self.logger.info('disabling fabric trunk on the interface ')
        if intf_type == 'ethernet':
            update = device.interface_ethernet_fabric_trunk_update
        elif intf_type == 'gigabitethernet':
            update = device.interface_gigabitethernet_fabric_trunk_update
        elif intf_type == 'tengigabitethernet':
            update = device.interface_tengigabitethernet_fabric_trunk_update
        elif intf_type == 'fortygigabitethernet':
            update = device.interface_fortygigabitethernet_fabric_trunk_update
        elif intf_type == 'hundredgigabitethernet':
            update = device.interface_hundredgigabitethernet_fabric_trunk_update
        else:
            self.logger.error('intf_type %s is not supported',
                              intf_type)
            return False

        try:
            for intf in intf_name:
                self.logger.info("disabling fabric trunk on %s %s", intf_type, intf)
                conf_intf = update(intf, fabric_trunk_enable=True)
                if conf_intf[0] == 'True':
                    self.logger.info('disabling fabric trunk on %s %s is done', intf_type, intf)

                elif conf_intf[0] == 'False':
                    self.logger.error('disabling fabric trunk on %s %s failed due to %s',
                                      intf_type,
                                      intf,
                                      conf_intf[1][0][self.host]
                                      ['response']['json']['output'])
        except (KeyError, ValueError, AttributeError):
            self.logger.error('Invalid Input values while disabling fabric trunk')
            return False
        return True

    def _get_interface_switchport(self, device, intf_type, intf_name):
        method = 'interface_{}_get'.format(intf_type)
        get_intf = eval('device.{}'.format(method))
        get = get_intf(intf_name)
        if get[0]:
            output = get[1][0][self.host]['response']['json']['output']
        else:
            return None
        if output is not None:
            intf = output.itervalues().next()
            if 'switchport' in intf:
                return intf['switchport']

        return None
