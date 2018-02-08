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
import sys


class CreateVrrpe(NosDeviceAction):
    """
       Implements the logic to Enable VRRPE and Configure VIP and VMAC the on VDX Switches .
       This action acheives the below functionality
           1. Enable VRRPE V4/6
           2. Create the VRRPE extended group
           3. Associate the VIP and VMAC address
           4. Enable short path forwarding
    """

    def run(self, mgmt_ip, username, password, intf_type, intf_name, rbridge_id, vrid, virtual_ip):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)

        changes = self.switch_operation(intf_type, intf_name, rbridge_id, virtual_ip, vrid)

        return changes

    @log_exceptions
    def switch_operation(self, intf_type, intf_name, rbridge_id, virtual_ip, vrid):
        changes = {}
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info('successfully connected to %s to Enable'
                             ' VRRPE Configs', self.host)
            if device.suports_rbridge and rbridge_id is None:
                rbridge_id = self.vlag_pair(device)

            if rbridge_id:
                for rb_id in rbridge_id:
                    self.validate_supports_rbridge(device, rb_id)
                    changes = self._create_vrrpe(device, intf_type, intf_name,
                                                 rb_id, virtual_ip, vrid)
            else:
                self.validate_supports_rbridge(device, rbridge_id)
                changes = self._create_vrrpe(device, intf_type, intf_name,
                                             rbridge_id, virtual_ip, vrid)
        return changes

    def _create_vrrpe(self, device, intf_type, intf_name, rbridge_id, virtual_ip, vrid):
        changes = {}
        changes['pre_validation'] = self._check_requirements(
            device, intf_type=intf_type, intf_name=intf_name,
            rbridge_id=rbridge_id, vrid=vrid, virtual_ip=virtual_ip)

        if changes['pre_validation'] != '':
            ip_version = int(changes['pre_validation'])

            changes['start_vrrpe'] = self._start_vrrpe(
                device,
                rbridge_id=rbridge_id,
                ip_version=ip_version)

            changes['vrrpe_vip'] = self._create_vrrpe_vip(
                device,
                intf_type=intf_type, intf_name=intf_name,
                rbridge_id=rbridge_id,
                virtual_ip=virtual_ip,
                vrid=vrid,
                ip_version=ip_version)

            if changes['vrrpe_vip']:
                changes['vrrpe_vmac'] = self._create_vrrpe_vmac(
                    device,
                    intf_type=intf_type, intf_name=intf_name,
                    rbridge_id=rbridge_id,
                    vrid=vrid,
                    ip_version=ip_version)

            if changes['vrrpe_vmac']:
                changes['vrrpe_spf'] = self._create_vrrpe_spf(
                    device,
                    intf_type=intf_type, intf_name=intf_name,
                    rbridge_id=rbridge_id,
                    vrid=vrid,
                    ip_version=ip_version)

        self.logger.info(
            'closing connection to %s after Enabling VRRPE - all done!',
            self.host)
        return changes

    def _check_requirements(self, device, intf_type, intf_name, vrid, rbridge_id,
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

        """
        # Check if the VRRP-E/VRRPV3 is pre-existing
        version_to_validate = 6 if ip_version == 4 else 4

        proto = device.services.vrrpe(get=True, ip_version=int(version_to_validate),
                                      rbridge_id=rbridge_id)

        if proto['ipv%s_vrrpe' % version_to_validate]:
            raise ValueError('Device is pre-configured with ip version %s' %
                             version_to_validate)

        """
        # validate supported interface type for vrrpe
        device.interface.vrrpe_supported_intf(intf_type=intf_type)

        # Verify if the VRRPE configs pre-exist
        if intf_type == 've':
            vlan_list = device.interface.ve_interfaces(rbridge_id=rbridge_id)
            config = self._validate_vip_vrid(device, vlan_list, 'Ve',
                       intf_name, ip_version, virtual_ip, vrid, rbridge_id)

            if not config[0]:
                self.logger.error('Ve %s is not available' % intf_name)
                raise ValueError('Ve %s is not present on the device' % (intf_name))

        if intf_type == 'ethernet':
            eth_list = device.interface.get_eth_l3_interfaces()
            config = self._validate_vip_vrid(device, eth_list, 'eth',
                    intf_name, ip_version, virtual_ip, vrid, rbridge_id)

            if not config[0]:
                self.logger.error('eth l3 intf %s is not available' % intf_name)
                raise ValueError('eth l3 intf %s is not present on the device' % (intf_name))

        if str(config[1]) == '' and config[2] is False:
            sys.exit(-1)

        return str(config[1])

    def _validate_vip_vrid(self, device, intf_list, intf_type, intf_name,
              ip_version, virtual_ip, vrid, rbridge_id):
        """
           validate whehter vip and vrid already present
        """

        intf_present = False
        idempotent_check = False
        if intf_type == 'Ve':
            int_type = 've'
        else:
            int_type = 'ethernet'

        for each_intf in intf_list:
            if intf_type in each_intf['if-name']:
                tmp_ip_version = ip_version
                if tmp_ip_version == '':
                    tmp_ip_version = 4
                vip_get = device.interface.vrrpe_vip(
                    get=True, int_type=int_type,
                    name=each_intf['if-name'].split()[1],
                    rbridge_id=rbridge_id)

                if each_intf['if-name'].split()[1] == intf_name:
                    intf_present = True
                    for each_entry in vip_get:
                        if self._is_same_vip(each_entry['vip'], virtual_ip) \
                                and each_entry['vrid'] == vrid:
                            self.logger.info(
                                'VRRP Extended group %s & associations '
                                'are pre-existing in %s %s' %
                                (vrid, intf_type, intf_name))
                            ip_version = ''
                            idempotent_check = True
                        elif self._is_same_vip(each_entry['vip'], virtual_ip)\
                                and each_entry['vrid'] != vrid:
                            self.logger.error(
                                'VIP %s is associated to a different '
                                'VRRPE group %s in %s %s' %
                                (virtual_ip, each_entry['vrid'],
                                intf_type, intf_name))
                            ip_version = ''
                        elif not self._is_same_vip(each_entry['vip'], virtual_ip) \
                                and each_entry['vrid'] == vrid:
                            self.logger.error(
                                'VRID %s is either associated to '
                                'a different IP %s or there is no '
                                'association existing in %s %s' %
                                (vrid, each_entry['vip'], intf_type, intf_name))
                            ip_version = ''

                elif each_intf['if-name'].split()[1] != intf_name:
                    for each_entry in vip_get:
                        if self._is_same_vip(each_entry['vip'], virtual_ip) \
                                and each_entry['vrid'] == vrid:
                            self.logger.error(
                                'VRRP-E group %s & associations are'
                                ' pre-existing on different %s %s' %
                                (vrid, intf_type, each_intf['if-name'].split()[1]))
                            ip_version = ''
                        elif self._is_same_vip(each_entry['vip'], virtual_ip) \
                                and each_entry['vrid'] != vrid:
                            self.logger.error('VIP %s is already part of'
                                              ' a different %s %s' %
                                              (virtual_ip, intf_type,
                                               each_intf['if-name'].split()[1]))
                            ip_version = ''
        return (intf_present, ip_version, idempotent_check)

    def _is_same_vip(self, vip_list, vip):
        """
          Check wheter vip present in the vip_list based on its type
        """
        if(type(vip_list).__name__ == 'str'):
            if(vip_list == vip):
                return True
            else:
                return False
        else:
            for each_vip in vip_list:
                if(each_vip == vip):
                    return True
            return False

    def _start_vrrpe(self, device, rbridge_id, ip_version):
        """ Start the VRRPE service globally"""

        self.logger.info('Start the VRRPE v-%s service globally', ip_version)

        device.services.vrrpe(
            rbridge_id=rbridge_id,
            ip_version=str(ip_version))
        return True

    def _create_vrrpe_vip(self, device, intf_type, intf_name, rbridge_id,
            virtual_ip, vrid, ip_version):
        """ Create the VRRPE extender group and associate the VIP """

        self.logger.info('Create the VRRPE extender group %s'
                         ' and associate the VIP service %s',
                         vrid, virtual_ip)
        device.interface.vrrpe_vrid(int_type=intf_type,
                                    name=intf_name,
                                    vrid=vrid,
                                    version=ip_version,
                                    rbridge_id=rbridge_id)

        device.interface.vrrpe_vip(name=intf_name, int_type=intf_type,
                                   vip=virtual_ip,
                                   vrid=vrid, rbridge_id=rbridge_id,
                                   version=int(ip_version))
        return True

    def _create_vrrpe_vmac(self, device, intf_type, intf_name, vrid,
                           rbridge_id, ip_version):
        """ Associate the VMAC to the extender group"""

        try:

            self.logger.info('Associating the VMAC to the extender '
                             'group %s', vrid)
            device.interface.vrrpe_vmac(int_type=intf_type, vrid=vrid,
                                        rbridge_id=rbridge_id,
                                        name=intf_name, version=int(ip_version))
        except (ValueError, KeyError):
            self.logger.exception('Unable to set VRRPe VMAC  %s',
                                  vrid)

            raise ValueError('Unable to set VRRPe VMAC  %s',
                             vrid)
        return True

    def _create_vrrpe_spf(self, device, intf_type, intf_name, rbridge_id,
            vrid, ip_version):
        """ Enable short path forwarding on the extender group"""

        try:
            self.logger.info('Enable SPF on the extender group %s', vrid)
            device.interface.vrrpe_spf_basic(int_type=intf_type, vrid=vrid,
                                             name=intf_name,
                                             rbridge_id=rbridge_id, version=ip_version)
        except (ValueError, KeyError):
            self.logger.exception('Invalid input values vrid,intf_name '
                                  '%s %s' % (vrid, intf_name))

            raise ValueError('Invalid input values vrid,intf_name '
                             '%s %s' % (vrid, intf_name))
        return True
