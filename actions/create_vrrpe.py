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
from ipaddress import ip_interface


class CreateVrrpe(NosDeviceAction):
    """
       Implements the logic to Enable VRRPE and Configure VIP and VMAC the on VDX Switches .
       This action acheives the below functionality
           1. Enable VRRPE V4/6
           2. Create the VRRPE extended group
           3. Associate the VIP and VMAC address
           4. Enable short path forwarding
    """

    def run(self, mgmt_ip, username, password, rbridge_id, ve_name, vrid, virtual_ip, virtual_mac):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}

        with self.mgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s to Enable VRRPE Configs', self.host)
            changes['pre_validation'] = self._check_requirements(device, rbridge_id=rbridge_id,
                                                           vrid=vrid, ve_name=ve_name,
                                                           virtual_ip=virtual_ip,
                                                           virtual_mac=virtual_mac)
            if changes['pre_validation'] != '':
                ip_version = changes['pre_validation']
                changes['start_vrrpe'] = self._start_vrrpe(device, rbridge_id=rbridge_id,
                                                           ip_version=ip_version)
                changes['vrrpe_vip'] = self._create_vrrpe_vip(device, rbridge_id=rbridge_id,
                                                             ip_version=ip_version,
                                                             ve_name=ve_name,
                                                             virtual_ip=virtual_ip, vrid=vrid)
                if changes['vrrpe_vip']:
                    changes['vrrpe_vmac'] = self._create_vrrpe_vmac(device, ve_name=ve_name,
                                                               rbridge_id=rbridge_id,
                                                               virtual_mac=virtual_mac, vrid=vrid)
                if changes['vrrpe_vmac']:
                    changes['vrrpe_spf'] = self._create_vrrpe_spf(device, rbridge_id=rbridge_id,
                                                                  ve_name=ve_name, vrid=vrid)
            self.logger.info('closing connection to %s after Enabling VRRPE - all done!', self.host)

        return changes

    def _check_requirements(self, device, ve_name, vrid, rbridge_id, virtual_ip,
                            virtual_mac):
        """ Verify if the VRRPE configs are pre-configured """

        # Verify if the VIP address already exists
        try:
            tmp_ip = ip_interface(unicode(virtual_ip))
            ip_version = tmp_ip.version
        except ValueError:
            self.logger.error('Invalid Virtual IP Address %s', virtual_ip)

        if len(unicode(virtual_ip).split("/")) != 1:
            raise ValueError('Pass VIP address without netmask', virtual_ip)

        # Check if the VRRP-E/VRRPV3 is pre-existing
        for ip_ver in ['4', '6']:
            proto = device.services.vrrpe(get=True, ip_version=ip_ver, rbridge_id=rbridge_id)
            proto_status = proto.data.find('.//{*}vrrp-extended')
            if proto_status is not None:
                if ip_ver != str(ip_version):
                    raise ValueError('Device is pre-configured with ip version', ip_ver)

        # Verify if the VRRPE configs pre-exist
        vlan_list = device.interface.ve_interfaces()
        for each_ve in vlan_list:
            if 'Ve' in each_ve['if-name']:
                tmp_ip_version = ip_version
                if tmp_ip_version == '':
                    tmp_ip_version = 4
                vip_get = device.interface.vrrpe_vip(get=True, int_type='ve',
                                                     name=each_ve['if-name'].split()[1],
                                                     rbridge_id=rbridge_id)
                if each_ve['if-name'].split()[1] == ve_name:
                    for each_entry in vip_get:
                        if each_entry['vip'] == virtual_ip and each_entry['vrid'] == vrid:
                            self.logger.info(
                                'VRRP Extended group %s & associations are pre-existing in VE %s',
                                vrid, ve_name)
                            ip_version = ''
                        elif each_entry['vip'] == virtual_ip and each_entry['vrid'] != vrid:
                            self.logger.info(
                                'VIP %s is associated to a different VRRPE group %s in VE %s',
                                virtual_ip, each_entry['vrid'], ve_name)
                            ip_version = ''
                        elif each_entry['vip'] != virtual_ip and each_entry['vrid'] == vrid:
                            self.logger.info(
                                'VRID %s is either associated to a different IP %s or there is no\
                                 association existing in VE %s',
                                vrid, each_entry['vip'], ve_name)
                            ip_version = ''
                elif each_ve['if-name'].split()[1] != ve_name:
                    for each_entry in vip_get:
                        if each_entry['vip'] == virtual_ip and each_entry['vrid'] == vrid:
                            self.logger.info(
                                'VRRP-E group %s & associations r pre-existing on different VE %s',
                                vrid, each_ve['if-name'].split()[1])
                            ip_version = ''
                        elif each_entry['vip'] == virtual_ip and each_entry['vrid'] != vrid:
                            self.logger.info('VIP %s is already part of a different VE %s',
                                      virtual_ip, each_ve['if-name'].split()[1])
                            ip_version = ''
        return str(ip_version)

    def _start_vrrpe(self, device, rbridge_id, ip_version):
        """ Start the VRRPE service globally"""

        self.logger.info('Start the VRRPE v-%s service globally on rbridge %s', ip_version,
                         rbridge_id)
        device.services.vrrpe(rbridge_id=rbridge_id, ip_version=ip_version)
        return True

    def _create_vrrpe_vip(self, device, rbridge_id, ve_name, virtual_ip, vrid, ip_version):
        """ Create the VRRPE extender group and associate the VIP """

        try:
            self.logger.info('Create the VRRPE extender group %s and associate the VIP service %s',
                             vrid, virtual_ip)
            device.interface.vrrpe_vip(name=ve_name, int_type='ve', vip=virtual_ip,
                                       vrid=vrid, rbridge_id=rbridge_id)
        except (ValueError, KeyError):
            self.logger.info('Invalid Input types while creating VRRPE group %s %s %s %s',
                             vrid, virtual_ip, rbridge_id, ve_name)
            return False
        return True

    def _create_vrrpe_vmac(self, device, ve_name, virtual_mac, vrid, rbridge_id):
        """ Associate the VMAC to the extender group"""

        try:
            if virtual_mac is not None:
                self.logger.info('Associating the VMAC %s to the extender group %s',
                                virtual_mac, vrid)
                device.interface.vrrpe_vmac(int_type='ve', vrid=vrid,
                                            rbridge_id=rbridge_id,
                                            virtual_mac=virtual_mac, name=ve_name)
            else:
                self.logger.info('Associating the VMAC to the extender group %s', vrid)
                device.interface.vrrpe_vmac(int_type='ve', vrid=vrid,
                                            rbridge_id=rbridge_id, name=ve_name)
        except (ValueError, KeyError):

            self.logger.info('Invalid input values vrid, rbridge_id, vmac %s %s %s',
                             vrid, rbridge_id, virtual_mac)
            return False
        return True

    def _create_vrrpe_spf(self, device, rbridge_id, ve_name, vrid):
        """ Enable short path forwarding on the extender group"""

        try:
            self.logger.info('Enable SPF on the extender group %s', vrid)
            device.interface.vrrpe_spf_basic(int_type='ve', vrid=vrid, name=ve_name,
                                             rbridge_id=rbridge_id)
        except (ValueError, KeyError):

            self.logger.info('Invalid input values vrid,rbridge_id,ve_name %s '
                             '%s %s', vrid, rbridge_id, ve_name)
            return False
        return True
