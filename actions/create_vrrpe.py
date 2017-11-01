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

from ipaddress import ip_interface

from ne_base import NosDeviceAction
from ne_base import log_exceptions


class CreateVrrpe(NosDeviceAction):
    """
       Implements the logic to Enable VRRPE and Configure VIP and VMAC the on VDX Switches .
       This action acheives the below functionality
           1. Enable VRRPE V4/6
           2. Create the VRRPE extended group
           3. Associate the VIP and VMAC address
           4. Enable short path forwarding
    """

    def run(self, mgmt_ip, username, password, rbridge_id, ve_name, vrid,
            virtual_ip):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)

        changes = self.switch_operation(rbridge_id, ve_name, virtual_ip, vrid)

        return changes

    @log_exceptions
    def switch_operation(self, rbridge_id, ve_name, virtual_ip,
                         vrid):
        changes = {}
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info('successfully connected to %s to Enable'
                             ' VRRPE Configs', self.host)

            self.validate_supports_rbridge(device, rbridge_id)

            changes['pre_validation'] = self._check_requirements(
                device, rbridge_id=rbridge_id,
                vrid=vrid, ve_name=ve_name,
                virtual_ip=virtual_ip)

            if changes['pre_validation'] != '':
                ip_version = int(changes['pre_validation'])

                changes['start_vrrpe'] = self._start_vrrpe(
                    device,
                    rbridge_id=rbridge_id,
                    ip_version=ip_version)

                changes['vrrpe_vip'] = self._create_vrrpe_vip(
                    device,
                    rbridge_id=rbridge_id,
                    ve_name=ve_name,
                    virtual_ip=virtual_ip,
                    vrid=vrid,
                    ip_version=ip_version)

                if changes['vrrpe_vip']:
                    changes['vrrpe_vmac'] = self._create_vrrpe_vmac(
                        device,
                        ve_name=ve_name,
                        rbridge_id=rbridge_id,
                        vrid=vrid,
                        ip_version=ip_version)

                if changes['vrrpe_vmac']:
                    changes['vrrpe_spf'] = self._create_vrrpe_spf(
                        device,
                        rbridge_id=rbridge_id,
                        ve_name=ve_name,
                        vrid=vrid,
                        ip_version=ip_version)

            self.logger.info(
                'closing connection to %s after Enabling VRRPE - all done!',
                self.host)
        return changes

    def _check_requirements(self, device, ve_name, vrid, rbridge_id,
                            virtual_ip):
        """ Verify if the VRRPE configs are pre-configured """

        # Verify if the VIP address already exists
        try:
            tmp_ip = ip_interface(unicode(virtual_ip))
            ip_version = tmp_ip.version
        except ValueError:
            self.logger.error('Invalid Virtual IP Address %s' % virtual_ip)
            raise ValueError('Invalid Virtual IP Address %s' % virtual_ip)

        if len(unicode(virtual_ip).split("/")) != 1:
            raise ValueError(
                'Pass VIP address without netmask %s' %
                virtual_ip)

        # Check if the VRRP-E/VRRPV3 is pre-existing

        version_to_validate = 6 if ip_version == 4 else 4

        proto = device.services.vrrpe(get=True, ip_version=int(version_to_validate),
                                      rbridge_id=rbridge_id)

        if proto['ipv%s_vrrpe' % version_to_validate]:
            raise ValueError('Device is pre-configured with ip version %s' %
                             version_to_validate)

        # Verify if the VRRPE configs pre-exist
        vlan_list = device.interface.ve_interfaces(rbridge_id=rbridge_id)

        ve_present = False
        for each_ve in vlan_list:
            if 'Ve' in each_ve['if-name']:
                tmp_ip_version = ip_version
                if tmp_ip_version == '':
                    tmp_ip_version = 4
                vip_get = device.interface.vrrpe_vip(
                    get=True, int_type='ve',
                    name=each_ve['if-name'].split()[1],
                    rbridge_id=rbridge_id)

                if each_ve['if-name'].split()[1] == ve_name:
                    ve_present = True
                    for each_entry in vip_get:
                        if each_entry['vip'] == virtual_ip \
                                and each_entry['vrid'] == vrid:
                            self.logger.error(
                                'VRRP Extended group %s & associations '
                                'are pre-existing in VE %s' %
                                (vrid, ve_name))
                            ip_version = ''
                        elif each_entry['vip'] == virtual_ip \
                                and each_entry['vrid'] != vrid:
                            self.logger.error(
                                'VIP %s is associated to a different '
                                'VRRPE group %s in VE %s' %
                                (virtual_ip, each_entry['vrid'], ve_name))
                            ip_version = ''
                        elif each_entry['vip'] != virtual_ip \
                                and each_entry['vrid'] == vrid:
                            self.logger.error(
                                'VRID %s is either associated to '
                                'a different IP %s or there is no\
                                 association existing in VE %s' %
                                (vrid, each_entry['vip'], ve_name))
                            ip_version = ''

                elif each_ve['if-name'].split()[1] != ve_name:
                    for each_entry in vip_get:
                        if each_entry['vip'] == virtual_ip \
                                and each_entry['vrid'] == vrid:
                            self.logger.error(
                                'VRRP-E group %s & associations are'
                                ' pre-existing on different VE %s' %
                                (vrid, each_ve['if-name'].split()[1]))
                            ip_version = ''
                        elif each_entry['vip'] == virtual_ip \
                                and each_entry['vrid'] != vrid:
                            self.logger.error('VIP %s is already part of'
                                              ' a different VE %s' %
                                              (virtual_ip,
                                               each_ve['if-name'].split()[1]))
                            ip_version = ''
        if not ve_present:
            self.logger.error('Ve %s is not available' % ve_name)
            raise ValueError('Ve %s is not present on the device' % (ve_name))

        return str(ip_version)

    def _start_vrrpe(self, device, rbridge_id, ip_version):
        """ Start the VRRPE service globally"""

        self.logger.info('Start the VRRPE v-%s service globally', ip_version)

        device.services.vrrpe(
            rbridge_id=rbridge_id,
            ip_version=str(ip_version))
        return True

    def _create_vrrpe_vip(self, device, rbridge_id, ve_name, virtual_ip,
                          vrid, ip_version):
        """ Create the VRRPE extender group and associate the VIP """

        try:
            self.logger.info('Create the VRRPE extender group %s'
                             ' and associate the VIP service %s',
                             vrid, virtual_ip)

            device.interface.vrrpe_vrid(int_type='ve',
                                        name=ve_name,
                                        vrid=vrid,
                                        version=ip_version,
                                        rbridge_id=rbridge_id)

            device.interface.vrrpe_vip(name=ve_name, int_type='ve',
                                       vip=virtual_ip,
                                       vrid=vrid, rbridge_id=rbridge_id,
                                       version=int(ip_version))
        except (ValueError, KeyError):
            self.logger.exception('Invalid Input types while '
                                  'creating VRRPE group %s %s %s' %
                                  (vrid, virtual_ip, ve_name))
            raise ValueError('Invalid Input types while '
                             'creating VRRPE group %s %s %s' %
                             (vrid, virtual_ip, ve_name))
        return True

    def _create_vrrpe_vmac(self, device, ve_name, vrid,
                           rbridge_id, ip_version):
        """ Associate the VMAC to the extender group"""

        try:

            self.logger.info('Associating the VMAC to the extender '
                             'group %s', vrid)
            device.interface.vrrpe_vmac(int_type='ve', vrid=vrid,
                                        rbridge_id=rbridge_id,
                                        name=ve_name, version=int(ip_version))
        except (ValueError, KeyError):
            self.logger.exception('Unable to set VRRPe VMAC  %s',
                                  vrid)

            raise ValueError('Unable to set VRRPe VMAC  %s',
                             vrid)
        return True

    def _create_vrrpe_spf(self, device, rbridge_id, ve_name, vrid,
                          ip_version):
        """ Enable short path forwarding on the extender group"""

        try:
            self.logger.info('Enable SPF on the extender group %s', vrid)
            device.interface.vrrpe_spf_basic(int_type='ve', vrid=vrid,
                                             name=ve_name,
                                             rbridge_id=rbridge_id, version=ip_version)
        except (ValueError, KeyError):
            self.logger.exception('Invalid input values vrid,ve_name '
                                  '%s %s' % (vrid, ve_name))

            raise ValueError('Invalid input values vrid,ve_name '
                             '%s %s' % (vrid, ve_name))
        return True
