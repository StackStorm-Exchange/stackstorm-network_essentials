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
        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s to create switchport on Interface',
                             self.host)
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
                        device, intf_type, intf_name, vlan_id)
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
                    changes['switchport_access_config'] = self._create_switchport(device,
                                                                                  intf_type,
                                                                                  intf_name,
                                                                                  vlan_id)

            self.logger.info(
                'closing connection to %s after configuring switch port on interface -- all done!',
                self.host)
        return changes

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

    def _check_requirements_switchport_exists(self, device, intf_type, intf_name, vlan_id):
        """ Fail the task if switch port exists.
        """
        try:
            return_code = device.interface.switchport(int_type=intf_type, name=intf_name,
                                                      get='True')

            if return_code is not None:
                result = device.interface.switchport_list
                for intf in result:
                    if intf['interface-name'] == intf_name:
                        if intf['mode'] == 'access':
                            if intf['vlan-id'] is not None:
                                for vid in intf['vlan-id']:
                                    if int(vid) == vlan_id:
                                        return False
                            else:
                                return True
                        else:
                            raise ValueError("Switchport trunk already on Interface,\
                              Pls removed and re - configure")
        except (ValueError, IndexError, KeyError), e:
            raise ValueError('Fetching switch port mode failed %s', str(e))
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
            device.interface.switchport(int_type=intf_type, name=intf_name)
            device.interface.acc_vlan(int_type=intf_type, name=intf_name, vlan=vlan_id)
            return True
        except ValueError, e:
            raise ValueError('Configuring Switch port access failed due to %s', str(e))
        except Exception, e:
            raise ValueError('Configuring Switch port access failed due to %s', str(e))

    def _disable_isl(self, device, intf_type, intf_name):
        """Disable ISL on the interface.
        """
        try:
            conf = device.interface.fabric_isl(get=True, name=intf_name, int_type=intf_type)
            if conf is None:
                return False
            self.logger.info("Disabling ISL on %s %s", intf_type, intf_name)
            device.interface.fabric_isl(enabled=False, name=intf_name, int_type=intf_type)
        except ValueError:
            self.logger.info('Disabling ISL is not supported on this platform/interface')
            return False
        except Exception as error:
            self.logger.info('Exception while disabling ISL on the device/interface %s', str(error))
            return False
        return True

    def _disable_fabric_trunk(self, device, intf_type, intf_name):
        """Disable ISL Fabric Trunk on the interface.
        """
        try:
            conf = device.interface.fabric_trunk(get=True, name=intf_name, int_type=intf_type)
            if conf is None:
                return False
            self.logger.info("Disabling fabric trunk on %s %s", intf_type, intf_name)
            device.interface.fabric_trunk(enabled=False, name=intf_name, int_type=intf_type)
        except ValueError:
            self.logger.info('Disabling Fabric Trunk is not supported on this platform/interface')
            return False
        except Exception as error:
            raise ValueError('Disabling Fabric Trunk is not supported on this platform/interface '
                             '%s', str(error))
        return True
