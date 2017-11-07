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


class CreateVe(NosDeviceAction):
    """
       Implements the logic to create interface VE and associate IP on
       VDX Switches .  This action acheives the below functionality
           1. Validate if the IPaddress is already associated to the VE
           2. Create a VE
           3. Associate the IP address to the VE
           4. Admin up on the interface VE
    """

    def run(self, mgmt_ip, username, password, rbridge_id, vlan_id, ve_id, ip_address,
            vrf_name, ipv6_use_link_local_only, skip_vlan_config):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        return self.switch_operation(rbridge_id, vlan_id, ve_id, ip_address,
                                     vrf_name, ipv6_use_link_local_only, skip_vlan_config)

    @log_exceptions
    def switch_operation(self, rbridge_id, vlan_id, ve_id, ip_address,
                         vrf_name, ipv6_use_link_local_only, skip_vlan_config):
        changes = {}

        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info('successfully connected to %s to create'
                             ' Ve', self.host)
            if device.os_type == 'nos':
                if rbridge_id is None:
                    rbridge_id = self.vlag_pair(device)
                if ip_address is None:
                    tmp_list = rbridge_id
                else:
                    if len(ip_address) == 1 and len(rbridge_id) >= 2:
                        ip_address = ip_address * len(rbridge_id)
                    elif len(rbridge_id) != len(ip_address):
                        raise ValueError('rbridge_id and ip_address lists are '
                                         'not matching', rbridge_id,
                                         ip_address)
                    tmp_list = zip(rbridge_id, ip_address)
            else:
                if ip_address is None:
                    tmp_list = [1]
                else:
                    tmp_list = zip([None], ip_address)
            if device.interface.is_ve_id_required():
                if ve_id is None:
                    self.logger.error('VE interface id is required for VE creation on MLX platform')
                    sys.exit(-1)
            else:
                # TBD change this for SLX as ve_id and vlan_id need not be same
                ve_id = vlan_id

            for each_rb in tmp_list:
                if ip_address is None:
                    rbridge_id = each_rb
                else:
                    rbridge_id = each_rb[0]
                    temp_address = each_rb[1]
                if device.os_type != 'nos':
                    rbridge_id = None
                if vrf_name is not None and vrf_name != '' and\
                        ip_address is not None and ip_address != '':
                    ip_address = temp_address
                    ve_exists =\
                        self._check_requirements_ve(device,
                                                    rbridge_id=rbridge_id,
                                                    vlan_id=vlan_id,
                                                    ve_name=ve_id)
                    changes['pre_validation_vrf'] =\
                        self._check_requirements_vrf(device,
                                                     rbridge_id=rbridge_id,
                                                     ve_name=ve_id,
                                                     vrf_name=vrf_name,
                                                     ip_address=ip_address)
                    changes['pre_validation_ip'] =\
                        self._check_requirements_ip(device,
                                                    rbridge_id=rbridge_id,
                                                    ve_name=ve_id,
                                                    vrf_name=vrf_name,
                                                    ip_address=ip_address)
                    if changes['pre_validation_vrf']:
                        if ve_exists:
                            changes['create_ve'] =\
                                self._create_ve(device,
                                                rbridge_id=rbridge_id,
                                                vlan_id=vlan_id,
                                                ve_name=ve_id,
                                                skip_vlan_config=skip_vlan_config)
                        changes['vrf_configs'] =\
                            self._create_vrf_forwarding(device,
                                                        vrf_name=vrf_name,
                                                        rbridge_id=rbridge_id,
                                                        ve_name=str(ve_id))
                    if changes['pre_validation_ip']:
                        changes['assign_ip'] =\
                            self._assign_ip_to_ve(device,
                                                  rbridge_id=rbridge_id,
                                                  ve_name=ve_id,
                                                  ip_address=ip_address)
                elif vrf_name is not None and vrf_name != '':
                    ve_exists =\
                        self._check_requirements_ve(device,
                                                    rbridge_id=rbridge_id,
                                                    vlan_id=vlan_id,
                                                    ve_name=ve_id)
                    changes['pre_validation_vrf'] =\
                        self._check_requirements_vrf(device,
                                                     rbridge_id=rbridge_id,
                                                     ve_name=ve_id,
                                                     vrf_name=vrf_name,
                                                     ip_address='')
                    if changes['pre_validation_vrf']:
                        if ve_exists:
                            changes['create_ve'] =\
                                self._create_ve(device,
                                                rbridge_id=rbridge_id,
                                                vlan_id=vlan_id,
                                                ve_name=ve_id,
                                                skip_vlan_config=skip_vlan_config)
                        changes['vrf_configs'] =\
                            self._create_vrf_forwarding(device,
                                                        vrf_name=vrf_name,
                                                        rbridge_id=rbridge_id,
                                                        ve_name=str(ve_id))
                elif ip_address is not None and ip_address != '':
                    ip_address = temp_address
                    ve_exists =\
                        self._check_requirements_ve(device,
                                                    rbridge_id=rbridge_id,
                                                    vlan_id=vlan_id,
                                                    ve_name=ve_id)
                    changes['pre_validation_ip'] =\
                        self._check_requirements_ip(device,
                                                    rbridge_id=rbridge_id,
                                                    ve_name=ve_id,
                                                    vrf_name='',
                                                    ip_address=ip_address)
                    if changes['pre_validation_ip']:
                        if ve_exists:
                            changes['create_ve'] =\
                                self._create_ve(device,
                                                rbridge_id=rbridge_id,
                                                vlan_id=vlan_id,
                                                ve_name=ve_id,
                                                skip_vlan_config=skip_vlan_config)
                        changes['assign_ip'] =\
                            self._assign_ip_to_ve(device,
                                                  rbridge_id=rbridge_id,
                                                  ve_name=ve_id,
                                                  ip_address=ip_address)
                elif ip_address is None and vrf_name is None:
                    ve_exists =\
                        self._check_requirements_ve(device,
                                                    rbridge_id=rbridge_id,
                                                    vlan_id=vlan_id,
                                                    ve_name=ve_id)
                    if ve_exists:
                        changes['create_ve'] =\
                            self._create_ve(device,
                                            rbridge_id=rbridge_id,
                                            vlan_id=vlan_id,
                                            ve_name=ve_id,
                                            skip_vlan_config=skip_vlan_config)
                self._admin_state(device, ve_name=ve_id,
                                  rbridge_id=rbridge_id)
                if ipv6_use_link_local_only:
                    ve_exists =\
                        self._check_requirements_ve(device,
                                                    rbridge_id=rbridge_id,
                                                    vlan_id=vlan_id,
                                                    ve_name=ve_id)
                    if ve_exists:
                        changes['create_ve'] = \
                            self._create_ve(device,
                                            rbridge_id=rbridge_id,
                                            ve_name=ve_id,
                                            skip_vlan_config=skip_vlan_config)
                    self._ipv6_link_local(device, name=ve_id,
                                          rbridge_id=rbridge_id)
            self.logger.info('closing connection to %s after creating Ve'
                             ' -- all done!', self.host)
        return changes

    def _check_requirements_ve(self, device, vlan_id, ve_name, rbridge_id):
        """ Verify if the VE is pre-existing """

        ves = device.interface.ve_interfaces(rbridge_id=rbridge_id)
        for each_ve in ves:
            tmp_ve_name = 'Ve ' + ve_name
            if each_ve['if-name'] == tmp_ve_name:
                self.logger.info('VE %s is pre-existing on rbridge_id '
                                 '%s', ve_name, rbridge_id)

                if device.interface.is_vlan_rtr_ve_config_req():
                    match = device.interface.vlan_router_ve(get=True, vlan_id=vlan_id)
                    if match:
                        self.logger.info('Router VE %s is pre-existing on vlan_id '
                                         '%s', match, ve_name)
                        return False
                else:
                    return False
        return True

    def _check_requirements_ip(self, device, ve_name, ip_address,
                               rbridge_id, vrf_name):
        """ Verify if the ip address is already associated to the VE """

        if len(unicode(ip_address).split("/")) != 2:
            raise ValueError('Pass IP address along with netmask.'
                             '(ip-address/netmask)', ip_address)
        tmp_ip = unicode(ip_address).split("/")[0]
        if not self.is_valid_ip(tmp_ip):
            raise ValueError('Invalid IP address %s', tmp_ip)

        ves = device.interface.ve_interfaces(rbridge_id=rbridge_id)
        for each_ve in ves:
            tmp_ve_name = 'Ve ' + ve_name
            if each_ve['ip-address'] != 'unassigned':
                if each_ve['if-name'] == tmp_ve_name and\
                        each_ve['ip-address'] == ip_address:
                    self.logger.info('Ip address %s on the VE %s is'
                                     ' pre-existing on rbridge_id %s',
                                     ip_address, ve_name, rbridge_id)
                    return False
                elif each_ve['if-name'] != tmp_ve_name and\
                        each_ve['ip-address'] == ip_address:
                    self.logger.error('Ip address %s is pre-assigned to a '
                                      'different %s on rbridge_id %s',
                                      ip_address, each_ve['if-name'],
                                      rbridge_id)
                    return False
                elif each_ve['if-name'] == tmp_ve_name and\
                        each_ve['ip-address'] != ip_address:
                    self.logger.error('Ve %s is pre-assigned with a different'
                                      ' IP %s on rbridge_id %s',
                                      ve_name, each_ve['ip-address'],
                                      rbridge_id)
                    return False
                elif ip_interface(unicode(ip_address)).network == \
                        ip_interface(unicode(each_ve['ip-address'])).network:
                    self.logger.error('IP address %s overlaps with a previously'
                                      ' configured IP subnet. Check %s on'
                                      ' rbridge_id %s',
                                      ip_address, each_ve['if-name'],
                                      rbridge_id)
                    return False

        if vrf_name == '':
            vrf_fwd = device.interface.add_int_vrf(get=True,
                                                   rbridge_id=rbridge_id,
                                                   name=ve_name, int_type='ve',
                                                   vrf_name=vrf_name)
            if vrf_fwd is not None:
                    config_tmp = vrf_fwd
                    self.logger.error('There is a VRF %s configured on the'
                                      ' VE %s on rbridge_id %s ,Remove the'
                                      ' VRF to configure the IP Address %s',
                                      config_tmp, ve_name, rbridge_id,
                                      ip_address)
                    return False

        if vrf_name is not None and vrf_name != '':
            ip_version = ip_interface(unicode(ip_address)).version
            afi = 'ipv4' if ip_version == 4 else 'ipv6'
            return self._validate_vrf_afi(device, rbridge_id,
                                          vrf_name, afi)

        return True

    def _validate_vrf_afi(self, device, rbridge_id, vrf_name, afi):
        """ Pre-checks to identify VRF address family configurations"""
        afi_status = device.interface.vrf_afi(
            get=True, rbridge_id=rbridge_id, vrf_name=vrf_name)
        if not afi_status[afi]:
            self.logger.error('To configure the ipv4/ipv6 address on the Ve on '
                              'rbridge_id %s, VRF Address Family-ipv4/ipv6 has '
                              'to be configured on VRF %s',
                              rbridge_id, vrf_name)
            sys.exit(-1)
        return True

    def _check_requirements_vrf(self, device, ve_name, vrf_name,
                                rbridge_id, ip_address):
        """ Verify if the vrf forwarding is enabled on the VE """

        ves = device.interface.ve_interfaces(rbridge_id=rbridge_id)
        vrf_output = device.interface.vrf(get=True, rbridge_id=rbridge_id)
        vrf_list = []
        for each_vrf in vrf_output:
            vrf_list.append(each_vrf['vrf_name'])

        for each_ve in ves:
            tmp_ve = 'Ve ' + ve_name
            if each_ve['ip-address'] != 'unassigned' and vrf_name in vrf_list:
                if each_ve['if-name'] == tmp_ve and each_ve['ip-address'] == ip_address:
                    self.logger.error('Ve %s is pre-assigned to this IP'
                                      ' address %s, and VRF %s on '
                                      'rbridge-id %s', ve_name,
                                      each_ve['ip-address'], vrf_name,
                                      rbridge_id)
                    return False
                elif each_ve['if-name'] == tmp_ve and each_ve['ip-address'] != '' \
                        and ip_address == '':
                    self.logger.error('There is an IP address %s pre-existing '
                                      'on the Ve %s, Remove the IP address '
                                      'before assigning the VRF %s on '
                                      'rbridge-id %s', each_ve['ip-address'],
                                      ve_name, vrf_name, rbridge_id)
                    return False
                elif each_ve['if-name'] == tmp_ve and each_ve['ip-address'] != ip_address:
                    self.logger.error('Ve %s is pre-assigned to a different '
                                      'IP address %s, Remove the IP address'
                                      'before assigning the VRF %s on '
                                      'rbridge-id %s', ve_name,
                                      each_ve['ip-address'], vrf_name,
                                      rbridge_id)
                    return False

        if vrf_name not in vrf_list:
            self.logger.error('Create VRF %s on rbridge-id %s before '
                             'assigning it to Ve', vrf_name, rbridge_id)
            return False

        vrf_fwd = device.interface.add_int_vrf(get=True, rbridge_id=rbridge_id,
                                               name=ve_name, int_type='ve',
                                               vrf_name=vrf_name)
        if vrf_fwd is not None:
            config_tmp = vrf_fwd
            if config_tmp == vrf_name:
                self.logger.info('VRF %s forwarding is pre-existing on Ve %s'
                                 ' on rbridge-id %s', vrf_name, ve_name,
                                 rbridge_id)
                return False
            elif config_tmp != vrf_name:
                self.logger.info('VRF forwarding is enabled on Ve %s but with '
                                 'a different VRF %s on rbride-id %s',
                                 ve_name, config_tmp, rbridge_id)
                return False
        return True

    def _create_ve(self, device, rbridge_id, vlan_id, ve_name, skip_vlan_config):
        """ Configuring the VE"""

        try:
            self.logger.info('Creating VE %s on rbridge-id %s',
                             ve_name, rbridge_id)
            if not skip_vlan_config:
                device.interface.add_vlan_int(vlan_id)
            if device.interface.is_vlan_rtr_ve_config_req() and not skip_vlan_config:
                device.interface.vlan_router_ve(vlan_id=vlan_id, ve_config=ve_name)
            device.interface.create_ve(enable=True, ve_name=ve_name,
                                       rbridge_id=rbridge_id)
        except (ValueError, KeyError) as e:
            self.logger.error('Invalid input value while creating Ve %s %s' % (ve_name, e.message))
            sys.exit(-1)
        return True

    def _assign_ip_to_ve(self, device, rbridge_id, ve_name, ip_address):
        """ Associate the IP address to the VE"""

        try:
            self.logger.info('Assigning IP address %s to VE %s on rbridge-id'
                             ' %s', ip_address, ve_name, rbridge_id)
            ip_address = ip_interface(unicode(ip_address))
            device.interface.ip_address(name=ve_name, int_type='ve',
                                        ip_addr=ip_address,
                                        rbridge_id=rbridge_id)
        except (ValueError, KeyError) as e:
            self.logger.error('Invalid Input values while assigning IP '
                             'address to Ve %s' % (e.message))
            sys.exit(-1)
        return True

    def _create_vrf_forwarding(self, device, rbridge_id, ve_name, vrf_name):
        """ Configure VRF is any"""

        try:
            self.logger.info('Configuring VRF %s on Ve %s on rbridge-id %s',
                             vrf_name, ve_name, rbridge_id)
            device.interface.add_int_vrf(int_type='ve', name=ve_name,
                                         rbridge_id=rbridge_id,
                                         vrf_name=vrf_name)
        except (ValueError, KeyError) as e:
            self.logger.error('Invalid Input values while configuring VRF %s on'
                              ' Ve %s on rbridge-id %s %s' % (vrf_name, ve_name,
                              rbridge_id, e.message))
            sys.exit(-1)
        return True

    def _admin_state(self, device, ve_name, rbridge_id):
        """ Admin settings on interface """

        # no-shut on the ve
        conf_ve = device.interface.admin_state(get=True,
                                               int_type='ve',
                                               name=ve_name,
                                               rbridge_id=rbridge_id)
        if not conf_ve:
            device.interface.admin_state(enabled=True, name=ve_name,
                                         int_type='ve', rbridge_id=rbridge_id)
            self.logger.info('Admin state setting on Ve %s is successfull',
                             ve_name)
            return True
        else:
            return False

    def _ipv6_link_local(self, device, name, rbridge_id):
        """ Enable ipv6 link local only on VE """

        try:
            link_check =\
                device.interface.ipv6_link_local(get=True, name=name,
                                                 rbridge_id=rbridge_id,
                                                 int_type='ve')
            if not link_check:
                device.interface.ipv6_link_local(name=name,
                                                 rbridge_id=rbridge_id,
                                                 int_type='ve')
                self.logger.info('Configuring IPV6 link local on Ve %s on'
                                 ' rbridge_id %s is '
                                 'successfull', name, rbridge_id)
                return True
            else:
                self.logger.info('IPV6 link local on Ve %s on rbridge_id %s'
                                 ' is pre-existing', name, rbridge_id)
                return False
        except (ValueError, KeyError) as e:
            self.logger.error('Invalid Input values while configuring IPV6 '
                              'link local %s ' % (e.message))
