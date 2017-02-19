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
import pyswitch.utilities
from pyswitch.device import Device


class DeleteVrrpe(NosDeviceAction):
    """
       Implements the logic to delete vrrpe configuration on VDX and SLX devices .
       This action achieves the below functionality
           1.Verify whether the vrrpe group exists in the switch or not.
           2.Delete vrrpe group on the vlan
    """

    def run(self, mgmt_ip, username, password, vlan_id, rbridge_id, vrrpe_group, ip_version):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}

        with Device(conn=self.conn, auth=self.auth) as device:
            self.validate_supports_rbridge(device, rbridge_id=rbridge_id)
            self.logger.info('successfully connected to %s to Delete VRRPe group',
                             self.host)
            changes['pre_check'] = self._validate_if_ve_exists(device, vlan_id, vrrpe_group)
            if changes['pre_check']:
                changes['VRRPe_group'] = self._delete_vrrpe(device, ve_name=vlan_id,
                                                            rbridge_id=rbridge_id,
                                                            vrrpe_group=vrrpe_group,
                                                            ip_version=ip_version)
            else:
                raise ValueError('Ve doesnt exist on the switch', vlan_id)
            self.logger.info('closing connection to %s after'
                             ' Deleting VRRPe group -- all done!', self.host)
        return changes

    def _validate_if_ve_exists(self, device, vlan_id, vrrpe_group):
        """validate vlan_id and ve
        """
        
        if vrrpe_group < 1 or vrrpe_group > 255 or vrrpe_group is None:
            raise ValueError('VRRPe group has to be in range of 1-255', vrrpe_group)
       
        if device.os_type == 'nos':
            valid_vlan = pyswitch.utilities.valid_vlan_id(vlan_id=vlan_id, extended=True)
        else:
            valid_vlan = pyswitch.utilities.valid_vlan_id(vlan_id=vlan_id, extended=False)

        if not valid_vlan:
            raise ValueError('Invalid vlan_id', vlan_id)

        interfaces = device.interface.vlans
        tmp_vlan_list = []
        for interface in interfaces:
            tmp_vlan_list.append((interface['vlan-id']))
        if vlan_id not in tmp_vlan_list:
            raise ValueError('vlan_id doesnt exist', vlan_id)

        is_exists = False
        vlan_list = device.interface.ve_interfaces()

        for each_ve in vlan_list:
            tmp_ve_name = 'Ve ' + vlan_id
            if each_ve['if-name'] == tmp_ve_name:
                is_exists = True
                break
        return is_exists

    def _delete_vrrpe(self, device, ve_name, rbridge_id, vrrpe_group, ip_version):
        """ Deleting VRRPe group"""

        is_vrrpe_present = True
        user_ve = str(ve_name)
        user_vrrpe = str(vrrpe_group)
        if ip_version is None or ip_version == 'IPv4':
            ip_version = 4
        else:
            ip_version = 6

        if rbridge_id and device.os_type == 'nos':
            for rbid in rbridge_id:
                rb = str(rbid)
                tmp_vrrpe_name = device.interface.vrrpe_vrid(get=True, int_type='ve', name=user_ve,
                                                             version=ip_version, rbridge_id=rb,
                                                             vrid=user_vrrpe)
                if tmp_vrrpe_name is None:
                    is_vrrpe_present = True
                elif user_vrrpe in tmp_vrrpe_name:
                    self.logger.info('Deleting VRRPe group %s on Ve %s from rbridge_id %s ',
                                     user_vrrpe, user_ve, rb)
                    device.interface.vrrpe_vrid(delete=True, int_type='ve', name=user_ve,
                                                version=ip_version, rbridge_id=rb, vrid=user_vrrpe)
                    is_vrrpe_present = False
        else:
            tmp_vrrpe_name = device.interface.vrrpe_vrid(get=True, name=user_ve, version=ip_version,
                                                         int_type='ve', vrid=user_vrrpe)
            if tmp_vrrpe_name is None:
                is_vrrpe_present = True
            elif user_vrrpe in tmp_vrrpe_name:
                self.logger.info('Deleting VRRPe group on Ve %s ', user_vrrpe)
                device.interface.vrrpe_vrid(delete=True, int_type='ve', name=user_ve,
                                            vrid=user_vrrpe, version=ip_version)
                is_vrrpe_present = False

        if not is_vrrpe_present:
            return True
        else:
            self.logger.info('VRRPe group %s does not exist on the Ve %s', user_vrrpe, user_ve)
            return False
