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
import sys


class CreateSwitchPort(NosDeviceAction):
    """
       Implements the logic to create switch-port on an interface on VDX Switches .
       This action acheives the below functionality
           1.Check specified interface is L2 or L3,continue only if L2 interface.
           2.Configure switch port access vlan with vlan specified by user on the L2 interface .
           3.Associate the mac-group to the access vlan
    """

    def run(self, mgmt_ip, username, password, intf_type, intf_name, vlan_id, mac_group_id):
        """Run helper methods to implement the desired state.
        """
        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as err:
            self.logger.error(err.message)
            sys.exit(-1)
        changes = {}
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info('successfully connected to %s to create switchport on Interface',
                             self.host)

            if mac_group_id is not None:
                mac_group_id = [str(e) for e in mac_group_id]
            # Validate MAC group id before we proceed with the switch call
            self._validate_macgroup_id(mac_group_id)
            if mac_group_id is not None:
                mac_group_id = self._pre_check_mac_group(device, mac_group_id)

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
                changes['switchport_doesnot_exists'], mac_gps, mac_ads =\
                    self._check_requirements_switchport_exists(
                        device, intf_type, intf_name, vlan_id, mac_group_id)
                if not changes['switchport_doesnot_exists']:
                    self.logger.info("SwitchPort configs are pre-existing on the device")
                if intf_type != 'port_channel' and changes['switchport_doesnot_exists']:
                    if device.os_type == 'nos':
                        changes['disable_isl'] = self._disable_isl(device,
                                                                   intf_type,
                                                                   intf_name)
                        changes[
                            'disable_fabric_trunk'] = self._disable_fabric_trunk(device, intf_type,
                                                                                 intf_name)
                if changes['switchport_doesnot_exists'] and mac_group_id is None:
                    changes['switchport_access_config'] = self._create_switchport(device,
                                                                                  intf_type,
                                                                                  intf_name,
                                                                                  vlan_id)
                if changes['switchport_doesnot_exists'] and mac_gps != []:
                    changes['mac_groups'] = self._config_switchport_mac_group(device,
                                                                              intf_type,
                                                                              intf_name,
                                                                              mac_gps)
                if changes['switchport_doesnot_exists'] and mac_ads != []:
                    changes['mac_groups'] = self._config_switchport_mac_address(device,
                                                                                intf_type,
                                                                                intf_name,
                                                                                mac_ads)
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

    def _check_requirements_switchport_exists(self, device, intf_type, intf_name, vlan_id,
                                              mac_group_id):
        """ Fail the task if switch port exists.
        """

        try:
            diff_grps, diff_macs = [], []
            return_code = device.interface.switchport(int_type=intf_type, name=intf_name,
                                                      get='True')

            if return_code is not None:
                result = device.interface.switchport_list
                for intf in result:
                    if intf['interface-name'] == intf_name:
                        if intf['mode'] == 'access':
                            if intf['vlan-id'] is not None:
                                for vid in intf['vlan-id']:
                                    if vid == vlan_id:
                                        return False, diff_grps, diff_macs
                                    elif int(vid) != 1:
                                        raise AttributeError('Switchport access is pre-existing on '
                                                         'with a different vlan_id %s' % vid)
                            else:
                                return True, diff_grps, diff_macs
                        else:
                            raise ValueError("Switchport trunk already on Interface,"
                                             "Pls removed and re - configure")

            if mac_group_id is not None:
                rt = device.interface.switchport_access_mac_group_create(get=True,
                                                                  intf_type=intf_type,
                                                                  intf_name=intf_name)
                if rt != []:
                    for each_vlan, each_mg in rt:
                        if each_vlan != vlan_id and each_mg in mac_group_id:
                            self.logger.error('Mac Group %s is already used with a different'
                                              ' vlan_id %s', each_mg, each_vlan)
                            raise ValueError('Mac Group is already used with a different Vlan')
                    tmp_groups = zip([vlan_id] * len(mac_group_id), mac_group_id)
                    valid_mgs = [items for items in rt if items in tmp_groups]
                    if valid_mgs != []:
                        if len(valid_mgs) == len(tmp_groups):
                            self.logger.info('vlan_id %s is pre-configured with Mac Groups %s',
                                             vlan_id, mac_group_id)
                        else:
                            self.logger.info('vlan_id %s is pre-configured with Mac Groups %s',
                                             vlan_id, valid_mgs)
                            diff_grps = set(valid_mgs).symmetric_difference(set(tmp_groups))
                            self.logger.info('To be configured Mac Groups %s', list(diff_grps))
                    else:
                        diff_grps = tmp_groups
                else:
                    diff_grps = zip([vlan_id] * len(mac_group_id), mac_group_id)

        except (ValueError, IndexError, KeyError) as e:
            self.logger.error('Fetching switch port mode or type check is failed %s',
                            str(e.message))
            sys.exit(-1)
        except AttributeError as e:
            self.logger.error('%s', str(e.message))
            sys.exit(-1)

        return True, list(diff_grps), list(diff_macs)

    def _validate_macgroup_id(self, mac_group_id):
        """ Verify if macgroup_id is valid """
        if mac_group_id is not None:
            for each_group in mac_group_id:
                if int(each_group) not in range(1, 501):
                    raise ValueError('Invalid MAC Group Id %s', each_group)

    def _pre_check_mac_group(self, device, mac_group_id):
        """ Check if mac group is pre-configured or not """

        out = device.interface.mac_group_create(get=True)
        if out is None:
            self.logger.error('Mac Groups %s are not present on the device', mac_group_id)
            raise ValueError('Mac Groups %s are not present on the Device' % (mac_group_id))
        else:
            mac_grps = [item for item in out if item in mac_group_id]
            if mac_grps == []:
                self.logger.error('Mac Groups %s not present on the device', mac_group_id)
                raise ValueError('Mac Groups %s not present on the Device' % (mac_group_id))
            if len(mac_grps) != len(mac_group_id):
                self.logger.info('Only %s Mac Groups are present on the device out of %s',
                                 mac_grps, mac_group_id)
        return mac_grps

    def _create_switchport(self, device, intf_type, intf_name, vlan_id):
        """Configuring Switch port access vlan on the interface with vlan"""

        try:
            self.logger.info('Configuring Switch port access on intf_name %s', intf_name)
            device.interface.switchport(int_type=intf_type, name=intf_name)
            device.interface.acc_vlan(int_type=intf_type, name=intf_name, vlan=vlan_id)
        except (ValueError, IndexError, KeyError), e:
            error_msg = str(e.message)
            self.logger.error("Configuring Switch port access failed due to %s", error_msg)
            sys.exit(-1)
        except UserWarning as e:
            self.logger.warning("configs are pre-existing %s", str(e.message))
        return True

    def _config_switchport_mac_group(self, device, intf_type, intf_name, mac_gps):
        """Associate the Mac Group to the Access Vlan.
        """

        try:
            self.logger.info("Configuring Switchport Access Vlan and Associating the Mac "
                             "Groups %s ", mac_gps)
            device.interface.switchport(int_type=intf_type, name=intf_name)
            for each_vlan, each_group in mac_gps:
                device.interface.switchport_access_mac_group_create(intf_name=intf_name,
                                                                    intf_type=intf_type,
                                                                    access_vlan_id=str(each_vlan),
                                                                    mac_group_id=each_group)
        except ValueError, e:
            raise ValueError("Configuring Switchport Access Vlan and Associating the Mac "
                             "Groups %s Failed due to %s", mac_gps, str(e))
        except KeyError, e:
            raise ValueError("Configuring Switchport Access Vlan and Associating the Mac "
                             "Groups %s Failed due to %s", mac_gps, str(e))
        except Exception, e:
            raise ValueError("Configuring Switchport Access Vlan and Associating the Mac "
                             "Groups %s Failed due to %s", mac_gps, str(e))
        return True

    def _config_switchport_mac_address(self, device, intf_type, intf_name, mac_ads):
        """Associate the Mac address to the Access Vlan.
        """

        try:
            self.logger.info("Configuring Switchport Access Vlan and Associating the Mac "
                             "Address %s ", mac_ads)
            device.interface.switchport(int_type=intf_type, name=intf_name)
            for each_vlan, each_group in mac_ads:
                device.interface.switchport_access_mac_create(intf_name=intf_name,
                                                              intf_type=intf_type,
                                                              access_vlan_id=str(each_vlan),
                                                              mac_address=each_group)
        except ValueError, e:
            raise ValueError("Configuring Switchport Access Vlan and Associating the Mac "
                             "Address %s Failed due to %s", mac_ads, str(e))
        except KeyError, e:
            raise ValueError("Configuring Switchport Access Vlan and Associating the Mac "
                             "Address %s Failed due to %s", mac_ads, str(e))
        except Exception, e:
            raise KeyError("Configuring Switchport Access Vlan and Associating the Mac "
                           "Address %s Failed due to %s", mac_ads, str(e))
        return True

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
