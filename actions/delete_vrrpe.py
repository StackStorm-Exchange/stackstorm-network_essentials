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
from pyswitch.device import Device
import sys


class DeleteVrrpe(NosDeviceAction):
    """
       Implements the logic to delete vrrpe configuration on VDX and SLX devices .
       This action achieves the below functionality
           1.Verify whether the vrrpe group exists in the switch or not.
           2.Delete vrrpe group on the vlan
    """

    def run(self, mgmt_ip, username, password, intf_type, intf_name,
            rbridge_id, vrrpe_group, ip_version):
        """Run helper methods to implement the desired state.
        """
        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as e:
            self.logger.error(e.message)
            sys.exit(-1)
        changes = {}

        with Device(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.validate_supports_rbridge(device, rbridge_id=rbridge_id)
            self.logger.info('successfully connected to %s to Delete VRRPe group',
                             self.host)

            # validate supported interface type for vrrpe
            device.interface.vrrpe_supported_intf(intf_type=intf_type)  # pylint: disable=no-member

            if intf_type == 've':
                changes['pre_check'] = self._validate_if_ve_exists(device, intf_name, vrrpe_group)
            else:
                changes['pre_check'] = self._validate_l3_eth_if_exists(device, intf_name,
                                                                       vrrpe_group)
            if changes['pre_check']:
                changes['VRRPe_group'] = self._delete_vrrpe(device,
                          intf_type=intf_type, intf_name=intf_name,
                          rbridge_id=rbridge_id, vrrpe_group=vrrpe_group,
                          ip_version=ip_version)
            else:
                raise ValueError('intferface %s does not exist on the switch' %
                               intf_name)
            self.logger.info('closing connection to %s after'
                             ' Deleting VRRPe group -- all done!', self.host)
        return changes

    def _validate_if_ve_exists(self, device, intf_name, vrrpe_group):
        """validate  ve
        """

        if vrrpe_group is None:
            raise ValueError('VRRPe group cannot be None')
        elif int(vrrpe_group) < 1 or int(vrrpe_group) > 255:
            raise ValueError('VRRPe group has to be in range of 1-255', vrrpe_group)
        is_exists = False
        vlan_list = device.interface.ve_interfaces()

        for each_ve in vlan_list:
            tmp_ve_name = 'Ve ' + intf_name
            if each_ve['if-name'] == tmp_ve_name:
                is_exists = True
                break
        return is_exists

    def _validate_l3_eth_if_exists(self, device, intf_name, vrrpe_group):
        """validate l3 ethernet interface
        """

        if vrrpe_group is None:
            raise ValueError('VRRPe group cannot be None')
        elif int(vrrpe_group) < 1 or int(vrrpe_group) > 255:
            raise ValueError('VRRPe group has to be in range of 1-255', vrrpe_group)
        is_exists = False
        eth_list = device.interface.get_eth_l3_interfaces()

        for each_intf in eth_list:
            tmp_intf_name = 'eth ' + intf_name
            if each_intf['if-name'] == tmp_intf_name:
                is_exists = True
                break
        return is_exists

    def _delete_vrrpe(self, device, intf_type, intf_name, rbridge_id, vrrpe_group, ip_version):
        """ Deleting VRRPe group"""

        is_vrrpe_present = True
        user_intf = str(intf_name)
        user_vrrpe = str(vrrpe_group)
        if ip_version is None or ip_version == 'IPv4':
            ip_version = 4
        else:
            ip_version = 6

        if rbridge_id and device.os_type == 'nos':
            for rbid in rbridge_id:
                rb = str(rbid)
                tmp_vrrpe_name = device.interface.vrrpe_vrid(get=True,
                     int_type=intf_type, name=user_intf, version=ip_version,
                     rbridge_id=rb, vrid=user_vrrpe)
                if tmp_vrrpe_name is None:
                    is_vrrpe_present = True
                elif user_vrrpe in tmp_vrrpe_name:
                    self.logger.info('Deleting VRRPe group %s on %s %s from rbridge_id %s ',
                                     user_vrrpe, intf_type, user_intf, rb)
                    device.interface.vrrpe_vrid(delete=True, int_type=intf_type,
                         name=user_intf, version=ip_version,
                         rbridge_id=rb, vrid=user_vrrpe)
                    is_vrrpe_present = False
        else:
            tmp_vrrpe_name = device.interface.vrrpe_vrid(get=True,
                        name=user_intf, version=ip_version, int_type=intf_type,
                        vrid=user_vrrpe)
            if tmp_vrrpe_name is None:
                is_vrrpe_present = True
            elif user_vrrpe in tmp_vrrpe_name:
                self.logger.info('Deleting VRRPe group on %s %s ', intf_type, user_vrrpe)
                device.interface.vrrpe_vrid(delete=True, int_type=intf_type,
                         name=user_intf, vrid=user_vrrpe, version=ip_version)

                is_vrrpe_present = False

        if not is_vrrpe_present:
            return True
        else:
            self.logger.info('VRRPe group %s does not exist on the %s %s',
            user_vrrpe, intf_type, user_intf)
            sys.exit(-1)
