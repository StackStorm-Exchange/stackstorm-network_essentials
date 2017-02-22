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


class CreateVe(NosDeviceAction):
    """
       Implements the logic to create interface VE and associate IP on VDX and SLX Switches .
       This action acheives the below functionality
           1. Validate if the IPaddress is already associated to the VE
           2. Create a VE
           3. Associate the IP address to the VE
           4. Admin up on the interface VE
    """

    def run(self, mgmt_ip, username, password, rbridge_id, vlan_id, ip_address, vrf_name,
            ipv6_use_link_local_only):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}
        device = self.get_device()

        # Get the os type: VDX or SLX
        os_type = self._get_os_type(device)

        if os_type == 'SLX-OS' and rbridge_id is not None:
            self.logger.error("Should not Enter rbridge id for SLX OS, "
                              "rbridge id not applicable for SLX OS")
            raise ValueError("Should not Enter rbridge id for SLX OS, "
                             "rbridge id not applicable for SLX OS")
        elif os_type == 'NOS' and rbridge_id is None:
            self.logger.error('rbridge_id cannot be None of NOS platform')
            raise ValueError('rbridge_id cannot be None of NOS platform')

        if ip_address is None:
            if os_type == 'NOS':
                tmp_list = rbridge_id
            elif os_type == 'SLX-OS':
                tmp_list = ['']
            else:
                self.logger.error("Device is not NOS or SLX")
                raise ValueError("Device is not NOS or SLX")

        else:
            if os_type == 'NOS':
                if len(ip_address) == 1 and len(rbridge_id) >= 2:
                    ip_address = ip_address * len(rbridge_id)
                elif len(rbridge_id) != len(ip_address):
                    raise ValueError('rbridge_id and ip_address lists are not matching',
                                     rbridge_id, ip_address)
                tmp_list = zip(rbridge_id, ip_address)
            elif os_type == 'SLX-OS':
                tmp_list = ip_address
        for each_rb in tmp_list:
            if ip_address is None:
                if os_type == 'NOS':
                    rbridge_id = each_rb
            else:
                if os_type == 'NOS':
                    rbridge_id = each_rb[0]
                    temp_address = each_rb[1]
                if os_type == 'SLX-OS':
                    temp_address = each_rb

            # VRF name and IP address are given
            if vrf_name and ip_address:
                ip_address = temp_address
                ve_exists = self._check_requirements_ve(device, rbridge_id=rbridge_id,
                                                        ve_name=vlan_id)
                changes['pre_validation_vrf'] = self._check_requirements_vrf(device,
                                                                             rbridge_id=rbridge_id,
                                                                             ve_name=vlan_id,
                                                                             vrf_name=vrf_name,
                                                                             ip_address=ip_address)

                changes['pre_validation_ip'] = self._check_requirements_ip(device,
                                                                           rbridge_id=rbridge_id,
                                                                           ve_name=vlan_id,
                                                                           vrf_name=vrf_name,
                                                                           ip_address=ip_address,
                                                                           os_type=os_type)

                if changes['pre_validation_vrf']:
                    if ve_exists:
                        changes['create_ve'] = self._create_ve(device, rbridge_id=rbridge_id,
                                                               ve_name=vlan_id)
                    changes['vrf_configs'] = self._create_vrf_forwarding(device,
                                                                         vrf_name=vrf_name,
                                                                         rbridge_id=rbridge_id,
                                                                         ve_name=str(vlan_id))
                if changes['pre_validation_ip']:
                    changes['assign_ip'] = self._assign_ip_to_ve(device, rbridge_id=rbridge_id,
                                                                 ve_name=vlan_id,
                                                                 ip_address=ip_address)

            # Only VRF name is given without ip address
            elif vrf_name:
                ve_exists = self._check_requirements_ve(device, rbridge_id=rbridge_id,
                                                        ve_name=vlan_id)
                changes['pre_validation_vrf'] = self._check_requirements_vrf(device,
                                                                             rbridge_id=rbridge_id,
                                                                             ve_name=vlan_id,
                                                                             vrf_name=vrf_name,
                                                                             ip_address='')

                if changes['pre_validation_vrf']:
                    if ve_exists:
                        changes['create_ve'] = self._create_ve(device, rbridge_id=rbridge_id,
                                                               ve_name=vlan_id)
                    changes['vrf_configs'] = self._create_vrf_forwarding(device,
                                                                         vrf_name=vrf_name,
                                                                         rbridge_id=rbridge_id,
                                                                         ve_name=str(vlan_id))

            # Only Ip address is given without vrf name
            elif ip_address:
                ip_address = temp_address
                ve_exists = self._check_requirements_ve(device, rbridge_id=rbridge_id,
                                                        ve_name=vlan_id)
                changes['pre_validation_ip'] = self._check_requirements_ip(device,
                                                                           rbridge_id=rbridge_id,
                                                                           ve_name=vlan_id,
                                                                           vrf_name='',
                                                                           ip_address=ip_address,
                                                                           os_type=os_type)

                if changes['pre_validation_ip']:
                    if ve_exists:
                        changes['create_ve'] = self._create_ve(device, rbridge_id=rbridge_id,
                                                               ve_name=vlan_id)
                    changes['assign_ip'] = self._assign_ip_to_ve(device, rbridge_id=rbridge_id,
                                                                 ve_name=vlan_id,
                                                                 ip_address=ip_address)

            # Both IP address and VRF name is not given
            elif ip_address is None and vrf_name is None:
                ve_exists = self._check_requirements_ve(device, rbridge_id=rbridge_id,
                                                        ve_name=vlan_id)
                if ve_exists:
                    changes['create_ve'] = self._create_ve(device, rbridge_id=rbridge_id,
                                                           ve_name=vlan_id)
            self._admin_state(device, ve_name=vlan_id, rbridge_id=rbridge_id)

            # if ipv6_use_link_local_only set true
            if ipv6_use_link_local_only:
                ve_exists = self._check_requirements_ve(device, rbridge_id=rbridge_id,
                                                        ve_name=vlan_id)
                if ve_exists:
                    changes['create_ve'] = self._create_ve(device, rbridge_id=rbridge_id,
                                                           ve_name=vlan_id)
                self._ipv6_link_local(device, name=vlan_id, rbridge_id=rbridge_id)
        self.logger.info('closing connection to %s after creating Ve -- all done!', self.host)

        return changes

    def _check_requirements_ve(self, device, ve_name, rbridge_id):
        """ Verify if the VE is pre-existing """

        ves = device.rbridge_id_interface_ve_get(rbridge_id=rbridge_id, ve=ve_name) \
            if rbridge_id else device.interface_ve_get(ve=ve_name)

        if ves[0]:
            if rbridge_id is not None:
                self.logger.info('VE %s is pre-existing on rbridge_id %s', ve_name, rbridge_id)
            else:
                self.logger.info('VE %s is already pre-existing', ve_name)
            return False
        elif not ves[0]:
            return True

    def _check_requirements_ip(self, device, ve_name, ip_address, rbridge_id, vrf_name, os_type):
        """ Verify if the ip address is already associated to the VE """

        try:
            ip_tmp = ip_interface(unicode(ip_address))
            ip_address = ip_tmp.with_prefixlen
        except ValueError:
            self.logger.info('Invalid IP address %s', ip_address)

        if len(unicode(ip_address).split("/")) != 2:
            raise ValueError('Pass IP address along with netmask.(ip-address/netmask)', ip_address)

        # Check if the rbridge_id is valid
        if os_type == 'NOS' and rbridge_id is not None:
            rbridge_chk = device.rbridge_id_get(rbridge_id)
            if not rbridge_chk[0]:
                return False

        # Check if ve has already an ip address assigned
        ves = device.rbridge_id_interface_ve_get(rbridge_id=rbridge_id,
                                                 ve=ve_name, resource_depth=2) \
            if rbridge_id else \
            device.interface_ve_get(resource_depth=2, ve=ve_name)
        if ves[0]:
            if ip_interface(unicode(ip_address)).version == 4:
                intf_ve_ipv4 = ves[1][0][self.host]['response']['json']['output']['Ve']['ip'][2] \
                    if rbridge_id else\
                    ves[1][0][self.host]['response']['json']['output']['Ve']['ip'][1]
            elif ip_interface(unicode(ip_address)).version == 6:
                intf_ve_ipv6 = \
                    ves[1][0][self.host]['response']['json']['output']['Ve']['ipv6']['address'][0] \
                    if rbridge_id else \
                    ves[1][0][self.host]['response']['json']['output']['Ve']['ipv6']['address']
            try:
                if ip_interface(unicode(ip_address)).version == 4:
                    ip_addr_chk = 'address' in intf_ve_ipv4
                    ve_addr = intf_ve_ipv4['address'][0]['address']
                elif ip_interface(unicode(ip_address)).version == 6:
                    ip_addr_chk = 'ipv6-address' in intf_ve_ipv6
                    ve_addr = intf_ve_ipv6['ipv6-address'][0]['address']
                    # Check if ve is already assigned with the given ip address
                if ip_addr_chk and (ip_address == ve_addr):
                    if rbridge_id is not None:
                        self.logger.info('Ip address %s on the VE %s is '
                                         'pre-existing on rbridge_id %s',
                                         ip_address, ve_name, rbridge_id)
                    else:
                        self.logger.info('Ip address %s on the VE %s is pre-existing',
                                         ip_address, ve_name)
                    return False
                    # Check if ve is assigned with a different ip address
                elif ip_addr_chk and (ve_addr != ip_address):
                    if rbridge_id is not None:
                        self.logger.info('Ve %s is pre-assigned with a different IP %s '
                                         'on rbridge_id %s', ve_name, ve_addr, rbridge_id)
                    else:
                        self.logger.info('Ve %s is pre-assigned with '
                                         'a different IP %s ', ve_name, ve_addr)
                    return False

            except KeyError:
                pass
                # Check if a vrf is already configured on the ve
            if vrf_name == '':
                chk_vrf_name = ves[1][0][self.host]['response']['json']['output']['Ve']['vrf']
                try:
                    if 'forwarding' in chk_vrf_name[0]:
                        if rbridge_id is not None:
                            self.logger.info('There is a VRF %s configured on the '
                                             'VE %s on rbridge_id %s ,Remove the VRF to '
                                             'configure the IP Address %s',
                                             chk_vrf_name[0]['forwarding'],
                                             ve_name, rbridge_id, ip_address)
                        else:
                            self.logger.info('There is a VRF %s configured on the VE %s '
                                             ',Remove the VRF to configure the IP Address %s',
                                             chk_vrf_name[0]['forwarding'], ve_name, ip_address)
                        return False
                except KeyError:
                    pass

        # IP Address Check for all interfaces

        ip_intf_list = self._get_ip_intf(device)

        if ip_intf_list is not None:
            for each_ip in ip_intf_list:
                intf = each_ip.split(' ')
                intf_name = intf[1]
                intf_type = intf[0].lower()
                ip_version = ip_interface(unicode(ip_address)).version
                if intf_type == 've':
                    rb_id = rbridge_id
                else:
                    rb_id = None
                ip_addr = self._get_interface_address(device, intf_type=intf_type,
                                                      intf_name=intf_name,
                                                      ip_version=ip_version, rbridge_id=rb_id)
                if ip_addr is not None:
                    if ip_address == ip_addr:
                        self.logger.info('Ip address %s is pre-assigned '
                                         'to a different %s %s', ip_address, intf_type,
                                         intf_name)
                        return False
                    elif ip_interface(unicode(ip_address)).network == \
                            ip_interface(unicode(ip_addr)).network:
                        self.logger.info('IP address %s overlaps with a previously '
                                         'configured IP subnet.', ip_address)
                        return False
        # Check if VRF Address Family is configured for the vrf
        if vrf_name:

            vrf_fwd_chk = device.rbridge_id_interface_ve_get(rbridge_id=rbridge_id,
                                                             ve=ve_name, resource_depth=2) \
                if rbridge_id else device.interface_ve_get(resource_depth=2, ve=ve_name)
            if vrf_fwd_chk[0]:
                vrf_fwd = vrf_fwd_chk[1][0][self.host]['response']['json']['output']['Ve']['vrf']
                if isinstance(vrf_fwd, list):
                    vrf_fwd = vrf_fwd.pop()
                if 'forwarding' in vrf_fwd:
                    if vrf_fwd['forwarding'] != vrf_name:
                        self.logger.info('There is a VRF %s already configured on the VE %s'
                                         ',Remove the VRF to configure the IP Address %s',
                                         vrf_fwd['forwarding'], ve_name, ip_address)
                        return False
                    else:
                        pass
                else:
                    pass
            vrfconf_chk = device.rbridge_id_vrf_get(rbridge_id=rbridge_id,
                                                    vrf=vrf_name, resource_depth=2) \
                if rbridge_id else device.vrf_get(vrf=vrf_name, resource_depth=2)
            if vrfconf_chk[0]:
                ipv4_conf = vrfconf_chk[1][0][
                    self.host]['response']['json']['output']['vrf']['address-family']['ipv4']
                ipv6_conf = vrfconf_chk[1][0][
                    self.host]['response']['json']['output']['vrf']['address-family']['ipv6']
                if ip_interface(unicode(ip_address)).version == 4:
                    chk_v4conf = 'unicast' in ipv4_conf
                    if chk_v4conf is not True:
                        self.logger.info('To configure the IP address on the Ve, '
                                         'VRF Address Family-ipv4 has to be configured on VRF %s',
                                         vrf_name)
                        return False
                elif ip_interface(unicode(ip_address)).version == 6:
                    chk_v6conf = 'unicast' in ipv6_conf
                    if chk_v6conf is not True:
                        self.logger.info('To configure the ipv6 address on the Ve, '
                                         'VRF Address Family-ipv6 has to be configured on VRF %s',
                                         vrf_name)
                        return False
            else:
                return False

        return True

    def _check_requirements_vrf(self, device, ve_name, vrf_name, rbridge_id, ip_address):
        """ Verify if the vrf forwarding is enabled on the VE """

        # Check if vrf is present or not
        vrf_present = device.rbridge_id_vrf_get(rbridge_id=rbridge_id) \
            if rbridge_id else device.vrf_get()
        vrf_list = []
        vrf_output = vrf_present[1][0][self.host]['response']['json']['output']
        if vrf_present[0] and vrf_output != '':
            vrf_output = vrf_present[1][0][self.host]['response']['json']['output']['vrf']
            if isinstance(vrf_output, dict):
                vrf_output = vrf_output['vrf-name']
                vrf_list.append(vrf_output)
            else:
                for each_vrf, _ in enumerate(vrf_output):
                    vrf_list.append(vrf_output[each_vrf]['vrf-name'])

        if vrf_name not in vrf_list:
            if rbridge_id is not None:
                self.logger.info('Create VRF %s on rbridge-id %s before assigning it to Ve',
                                 vrf_name, rbridge_id)
                return False
            else:
                self.logger.info('Create VRF %s before assigning it to Ve',
                                 vrf_name)
                return False

        vrf_fwd_chk = device.rbridge_id_interface_ve_get(rbridge_id=rbridge_id,
                                                         ve=ve_name, resource_depth=2) \
            if rbridge_id else device.interface_ve_get(resource_depth=2, ve=ve_name)

        if vrf_fwd_chk[0] and vrf_name in vrf_list:

            try:
                intf_ve_ipv4 = \
                    vrf_fwd_chk[1][0][self.host]['response']['json']['output']['Ve']['ip'][2] \
                    if rbridge_id else \
                    vrf_fwd_chk[1][0][self.host]['response']['json']['output']['Ve']['ip'][1]
                ip_addr_chk = 'address' in intf_ve_ipv4
                ve_addr = intf_ve_ipv4['address'][0]['address']

                if ip_addr_chk and ip_address == ve_addr:
                    if rbridge_id is not None:
                        self.logger.info('Ve %s is pre-assigned to this IP address %s '
                                         'and VRF %s on rbridge-id %s',
                                         ve_name, ve_addr, vrf_name, rbridge_id)
                    else:
                        self.logger.info('Ve %s is pre-assigned to this IP address %s '
                                         'and VRF %s on rbridge-id %s',
                                         ve_name, ve_addr, vrf_name, rbridge_id)
                    return False
                elif ip_addr_chk and ve_addr != '' and ip_address == '':
                    if rbridge_id is not None:
                        self.logger.info('There is an IP address %s pre-existing on the Ve %s, '
                                         'Remove the IP address before assigning the VRF %s on '
                                         'rbridge-id %s', ve_addr, ve_name, vrf_name, rbridge_id)
                    else:
                        self.logger.info('There is an IP address %s pre-existing on the Ve %s, '
                                         'Remove the IP address before assigning the VRF %s',
                                         ve_addr, ve_name, vrf_name)
                    return False
                elif ip_addr_chk and ve_addr != ip_address:
                    if rbridge_id is not None:
                        self.logger.info('Ve %s is pre-assigned to a different IP address %s, '
                                         'Remove the IP address before assigning the VRF %s '
                                         'on rbridge-id %s',
                                         ve_name, ve_addr, vrf_name, rbridge_id)
                    else:
                        self.logger.info('Ve %s is pre-assigned to a different IP address %s, '
                                         'Remove the IP address before assigning the VRF %s',
                                         ve_name, ve_addr, vrf_name)

                    return False
            except KeyError:
                pass

            try:
                intf_ve_ipv6 = vrf_fwd_chk[1][0][
                    self.host]['response']['json']['output']['Ve']['ipv6']['address'][0]
                ip_addr_chk = 'ipv6-address' in intf_ve_ipv6
                ve_addr = intf_ve_ipv6['ipv6-address'][0]['address']

                if ip_addr_chk and ip_address == ve_addr:
                    if rbridge_id is not None:
                        self.logger.info('Ve %s is pre-assigned to this IP address %s '
                                         'and VRF %s on rbridge-id %s',
                                         ve_name, ve_addr, vrf_name, rbridge_id)
                    else:
                        self.logger.info('Ve %s is pre-assigned to this IP address %s '
                                         'and VRF %s on rbridge-id %s',
                                         ve_name, ve_addr, vrf_name, rbridge_id)
                    return False
                elif ip_addr_chk and ve_addr != '' and ip_address == '':
                    if rbridge_id is not None:
                        self.logger.info('There is an IP address %s pre-existing on the Ve %s, '
                                         'Remove the IP address before assigning the VRF %s on '
                                         'rbridge-id %s', ve_addr, ve_name, vrf_name, rbridge_id)
                    else:
                        self.logger.info('There is an IP address %s pre-existing on the Ve %s, '
                                         'Remove the IP address before assigning the VRF %s',
                                         ve_addr, ve_name, vrf_name)
                    return False
                elif ip_addr_chk and ve_addr != ip_address:
                    if rbridge_id is not None:
                        self.logger.info('Ve %s is pre-assigned to a different IP address %s, '
                                         'Remove the IP address before assigning the VRF %s'
                                         'on rbridge-id %s',
                                         ve_name, ve_addr, vrf_name, rbridge_id)
                    else:
                        self.logger.info('Ve %s is pre-assigned to a different IP address %s, '
                                         'Remove the IP address before assigning the VRF %s',
                                         ve_name, ve_addr, vrf_name)

                    return False
            except KeyError:
                pass

            vrf_fwd = vrf_fwd_chk[1][0][self.host]['response']['json']['output']['Ve']['vrf']
            if isinstance(vrf_fwd, list):
                vrf_fwd = vrf_fwd.pop()
            try:
                if 'forwarding' in vrf_fwd:
                    if vrf_fwd['forwarding'] == vrf_name:
                        # Check if vrf forwarding with same vrfname is already present on ve
                        if rbridge_id is not None:
                            self.logger.info('VRF %s forwarding is pre-existing '
                                             'on Ve %s on rbridge-id %s',
                                             vrf_name, ve_name, rbridge_id)
                        else:
                            self.logger.info('VRF %s forwarding is pre-existing '
                                             'on Ve %s', vrf_name, ve_name)
                        return False
                    elif vrf_fwd['forwarding'] != vrf_name:
                        # Check if vrf forwarding with a differnt vrfname is present on ve
                        if rbridge_id is not None:
                            self.logger.info('VRF forwarding is enabled on Ve %s '
                                             'but with a different VRF %s on rbridge-id %s',
                                             ve_name, vrf_fwd['forwarding'], rbridge_id)
                        else:
                            self.logger.info('VRF forwarding is enabled on Ve %s '
                                             'but with a different VRF %s ',
                                             ve_name, vrf_fwd['forwarding'])
                        return False
            except KeyError:
                pass

        return True

    def _create_ve(self, device, rbridge_id, ve_name):
        """ Configuring the VE"""
        self.logger.info('Creating VE %s on rbridge_id %s', ve_name, rbridge_id) \
            if rbridge_id else \
            self.logger.info('Creating VE %s', ve_name)

        try:
            device.vlan_create(vlan=ve_name)
            create_ve = device.rbridge_id_interface_ve_create(rbridge_id=rbridge_id, ve=ve_name) \
                if rbridge_id else device.interface_ve_create(ve=ve_name)
            if not create_ve[0]:
                self.logger.error("Unable to create ve because %s",
                                  create_ve[1][0][self.host]['response']['json']['output'])
                return False
            else:
                self.logger.info("Ve successfully created")
                return True

        except (ValueError, KeyError):
            self.logger.info('Invalid Input values while creating to Ve')
            return False

    def _assign_ip_to_ve(self, device, rbridge_id, ve_name, ip_address):
        """ Associate the IP address to the VE"""

        try:
            self.logger.info('Assigning IP address %s to VE %s on rbridge_id %s',
                             ip_address, ve_name, rbridge_id) \
                if rbridge_id else \
                self.logger.info('Assigning IP address %s to VE %s', ip_address, ve_name)
            ip_address = ip_interface(unicode(ip_address))
            if ip_interface(unicode(ip_address)).version == 4:
                assign_ip = device.rbridge_id_interface_ve_ip_address_create(
                    rbridge_id=rbridge_id, ve=ve_name, address=(ip_address,)) \
                    if rbridge_id else \
                    device.interface_ve_ip_address_create(ve=ve_name, address=(ip_address,))
            elif ip_interface(unicode(ip_address)).version == 6:
                assign_ip = device.rbridge_id_interface_ve_ipv6_address_ipv6_address_create(
                    rbridge_id=rbridge_id, ve=ve_name, ipv6_address=(ip_address,)) \
                    if rbridge_id else \
                    device.interface_ve_ipv6_address_create(ve=ve_name,
                                                            ipv6_address=(ip_address,))
            if not assign_ip:
                self.logger.error('Unable to assign ip to ve %s because %s', ve_name,
                                  assign_ip[1][0][self.host]['response']['json']['output'])
                return False
            else:
                self.logger.info('Ip successfully assigned to ve %s', ve_name)
                return True
        except (ValueError, KeyError):
            self.logger.info('Invalid Input values while assigning IP address to Ve')
            return False

    def _create_vrf_forwarding(self, device, rbridge_id, ve_name, vrf_name):
        """ Configure VRF is any"""

        try:
            self.logger.info('Configuring VRF %s on Ve %s on rbridge_id %s',
                             vrf_name, ve_name, rbridge_id) if rbridge_id else \
                self.logger.info('Configuring VRF %s on Ve %s',
                                 vrf_name, ve_name)
            create_vrf_fwd = device.rbridge_id_interface_ve_vrf_update(
                rbridge_id=rbridge_id, ve=ve_name, forwarding=vrf_name) \
                if rbridge_id else \
                device.interface_ve_vrf_update(ve=ve_name, forwarding=vrf_name)
            if not create_vrf_fwd:
                self.logger.error('Unable to configure vrf %s on ve '
                                  '%s because %s', vrf_name, ve_name,
                                  create_vrf_fwd[1][0][self.host]['response']['json']['output'])
                return False
            else:
                self.logger.info('VRF %s successfully configured on ve %s', vrf_name, ve_name)
                return True
        except (ValueError, KeyError):
            self.logger.info('Invalid Input values while configuring VRF %s on'
                             'Ve %s', vrf_name, ve_name)
            return False

    def _admin_state(self, device, ve_name, rbridge_id):
        """ Admin settings on interface """

        # no-shut on the ve

        intf_state = device.rbridge_id_interface_ve_get(
            resource_depth=2, rbridge_id=rbridge_id, ve=ve_name) \
            if rbridge_id else device.interface_ve_get(resource_depth=2, ve=ve_name)
        if intf_state[0]:
            try:
                admin_state = intf_state[1][0][self.host]['response']['json']['output']['Ve']
                if 'shutdown' in admin_state and admin_state['shutdown'] == 'true':
                    admin_state = device.rbridge_id_interface_ve_update(
                        rbridge_id=rbridge_id, ve=ve_name, shutdown='False') \
                        if rbridge_id else \
                        device.interface_ve_update(ve=ve_name, global_ve_shutdown='False')
                    if not admin_state:
                        self.logger.error('Unable to set admin state on Ve %s because %s', ve_name,
                                          admin_state[1][0][
                                              self.host]['response']['json']['output'])
                    else:
                        self.logger.info('Admin state setting on Ve %s is successfull', ve_name)
                        return True
            except KeyError:
                self.logger.error('Unable to set admin state on Ve')
                return False

    def _ipv6_link_local(self, device, name, rbridge_id):
        """ Enable ipv6 link local only on VE """

        try:
            link_check = device.rbridge_id_interface_ve_get(rbridge_id=rbridge_id, ve=name) \
                if rbridge_id else device.interface_ve_get(ve=name)
            get_link_local = \
                link_check[1][0][self.host]['response']['json']['output']['Ve']['ipv6']['address']
            if 'use-link-local-only' in get_link_local:
                if rbridge_id is not None:
                    self.logger.info('IPV6 link local on Ve %s on rbridge_id %s is pre-existing',
                                     name, rbridge_id)
                else:
                    self.logger.info('IPV6 link local on Ve %s is pre-existing',
                                     name)
            else:
                ipv6_link = device.rbridge_id_interface_ve_ipv6_address_use_link_local_only_update(
                    rbridge_id=rbridge_id, ve=name, use_link_local_only='True') \
                    if rbridge_id else \
                    device.interface_ve_ipv6_address_use_link_local_only_update(
                        ve=name, use_link_local_only='True')
                if not ipv6_link:
                    self.logger.error('Unable to configure Ipv6 link local '
                                      'on Ve %s because %s', name,
                                      ipv6_link[1][0][self.host]['response']['json']['output'])
                else:
                    if rbridge_id is not None:
                        self.logger.info('Configuring IPV6 link local on Ve %s '
                                         'on rbridge_id %s is successfull', name, rbridge_id)
                    else:
                        self.logger.info('Configuring IPV6 link local '
                                         'on Ve %s is successfull', name)
                return True
        except (ValueError, KeyError):
            self.logger.info('Invalid Input values while configuring IPV6 link local')
            return False
