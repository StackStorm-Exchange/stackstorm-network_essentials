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


class CreateVrfEvpn(NosDeviceAction):

    """
       Implements the logic to Create a VRF for the EVPN tenants on VDX Switches .
       This action acheives the below functionality
           1. Create VRF
           2. Configure the route distinguisher
           3. Configure L3 VNI under vrf
           4. Configure target VPN exetended communites
    """

    def run(self, mgmt_ip, username, password, vrf_name, l3vni, route_distinguisher,
            ipv4_route_target_import_evpn, ipv4_route_target_export_evpn,
            ipv6_route_target_import_evpn, ipv6_route_target_export_evpn, rbridge_id):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}
        with self.mgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s to Create VRF for EVPN tenants',
                             self.host)
            if rbridge_id is None:
                rb_list = self.vlag_pair(device)
            else:
                rb_list = rbridge_id

            v4_import = ipv4_route_target_import_evpn
            v4_export = ipv4_route_target_export_evpn
            v6_import = ipv6_route_target_import_evpn
            v6_export = ipv6_route_target_export_evpn
            for temp in zip(rb_list, route_distinguisher):
                rd = temp[1]
                rbridge_id = str(temp[0])
                changes['pre_validation_vrf'] = self._check_requirements_vrf(device, rbridge_id,
                                                                             vrf_name)
                changes['pre_validation_rd'] = self._check_requirements_rd(device, rbridge_id,
                                                                           vrf_name,
                                                                           rd=rd)
                changes['pre_validation_l3vni'] = self._check_requirements_l3vni(device, rbridge_id,
                                                                                 vrf_name, l3vni)
                pre_validation_vpn = self._target_vpn_list(v4_import, v4_export,
                                                           v6_import, v6_export)

                if not changes['pre_validation_vrf']:
                    changes['create_vrf'] = self._create_vrf(device, vrf_name=vrf_name,
                                                             rbridge_id=rbridge_id)
                if not changes['pre_validation_rd']:
                    changes['configure_rd'] = self._configure_rd(device, vrf_name=vrf_name,
                                                                 rbridge_id=rbridge_id,
                                                                 rd=rd)
                if not changes['pre_validation_l3vni']:
                    changes['l3vni'] = self._vrf_l3vni(device, rbridge_id=rbridge_id,
                                                       vrf_name=vrf_name, l3vni=l3vni)
                if pre_validation_vpn != '':
                    if pre_validation_vpn['v4_rts'] != [] and\
                            pre_validation_vpn['v4_rts_value'] != [] and\
                            pre_validation_vpn['v6_rts'] != [] and\
                            pre_validation_vpn['v6_rts_value'] != []:
                        for temp in zip(pre_validation_vpn['v4_rts'],
                                pre_validation_vpn['v4_rts_value']):
                            changes['target_evpn'] = self._vrf_afi_rt_evpn(device,
                                                                           rbridge_id=rbridge_id,
                                                                           vrf_name=vrf_name,
                                                                           afi='ip',
                                                                           rt=temp[0],
                                                                           rt_value=temp[1])
                        for temp in zip(pre_validation_vpn['v6_rts'],
                                pre_validation_vpn['v6_rts_value']):
                            changes['target_evpn'] = self._vrf_afi_rt_evpn(device,
                                                                           rbridge_id=rbridge_id,
                                                                           vrf_name=vrf_name,
                                                                           afi='ipv6',
                                                                           rt=temp[0],
                                                                           rt_value=temp[1])
                    elif pre_validation_vpn['v4_rts'] != [] and\
                            pre_validation_vpn['v4_rts_value'] != []:
                        for temp in zip(pre_validation_vpn['v4_rts'],
                                pre_validation_vpn['v4_rts_value']):
                            changes['target_evpn'] = self._vrf_afi_rt_evpn(device,
                                                                           rbridge_id=rbridge_id,
                                                                           vrf_name=vrf_name,
                                                                           afi='ip',
                                                                           rt=temp[0],
                                                                           rt_value=temp[1])
                    elif pre_validation_vpn['v6_rts'] != [] and\
                            pre_validation_vpn['v6_rts_value'] != []:
                        for temp in zip(pre_validation_vpn['v6_rts'],
                                pre_validation_vpn['v6_rts_value']):
                            changes['target_evpn'] = self._vrf_afi_rt_evpn(device,
                                                                           rbridge_id=rbridge_id,
                                                                           vrf_name=vrf_name,
                                                                           afi='ipv6',
                                                                           rt=temp[0],
                                                                           rt_value=temp[1])
            self.logger.info('closing connection to %s after Enabling VRRPE - all done!',
                             self.host)
        return changes

    def _check_requirements_vrf(self, device, rbridge_id, vrf_name):
        """ pre-checks to identify the existing vrf configurations"""

        vrf_output = device.interface.vrf(get=True, rbridge_id=rbridge_id)
        is_existing = False
        for each_vrf in vrf_output:
            if each_vrf['vrf_name'] == vrf_name:
                is_existing = True
                self.logger.info('VRF %s is pre-existing on rbridge_id %s',
                                 vrf_name, rbridge_id)
        return is_existing

    def _check_requirements_rd(self, device, rbridge_id, vrf_name, rd):
        """ pre-checks to identify the existing rd configurations"""

        rd_output = device.interface.vrf_route_distiniguisher(get=True, vrf_name=vrf_name,
                                                              rbridge_id=rbridge_id, rd=rd)
        is_existing = False
        for rd_each in rd_output:
            if rd_each['vrf_name'] == vrf_name and rd_each['rd'] == rd:
                self.logger.info('VRF %s with rd %s is pre-existing on rbridge_id %s',
                                 vrf_name, rd, rbridge_id)
                is_existing = True
                break
            elif rd_each['vrf_name'] != vrf_name and rd_each['rd'] == rd:
                self.logger.info('RD %s is pre-assigned to a different VRF %s on rbridge_id %s',
                                 rd, vrf_name, rbridge_id)
                is_existing = True
                break

        return is_existing

    def _check_requirements_l3vni(self, device, rbridge_id, vrf_name, l3vni):
        """ pre-checks to identify the existing l3vni configurations"""

        l3vni_output = device.interface.vrf_l3vni(get=True, vrf_name=vrf_name,
                                                  rbridge_id=rbridge_id,
                                                  l3vni=l3vni)
        is_existing = False
        for each_l3vni in l3vni_output:
            if each_l3vni['vrf_name'] != vrf_name and each_l3vni['l3vni'] == str(l3vni):
                self.logger.info('l3vni %s is pre-assigned to a different VRF %s on rbridge_id %s',
                                 l3vni, vrf_name, rbridge_id)
                is_existing = True
                break
            elif each_l3vni['vrf_name'] == vrf_name and each_l3vni['l3vni'] == str(l3vni):
                self.logger.info('VRF %s to l3vni %s mapping is pre-existing on rbridge_id %s',
                                 vrf_name, l3vni, rbridge_id)
                is_existing = True
                break

        return is_existing

    def _create_vrf(self, device, rbridge_id, vrf_name):
        """ create VRF """

        try:
            self.logger.info('Creating VRF %s on rbridge_id %s', vrf_name, rbridge_id)
            device.interface.vrf(vrf_name=vrf_name, rbridge_id=rbridge_id)
        except (ValueError, KeyError):
            self.logger.info('Invalid Input types while creating VRF %s on rbridge_id %s',
                             vrf_name, rbridge_id)
            return False
        return True

    def _configure_rd(self, device, rbridge_id, vrf_name, rd):
        """ Configure route distinguisher on a give VRF """

        try:
            self.logger.info('Configuring RD %s on VRF %s on rbridge_id %s',
                             rd, vrf_name, rbridge_id)
            device.interface.vrf_route_distiniguisher(vrf_name=vrf_name, rbridge_id=rbridge_id,
                                                      rd=rd)
        except (ValueError, KeyError):
            self.logger.info('Invalid input types while configuring RD %s on VRF %s'
                             ' on rbridge_id %s',
                             rd, vrf_name, rbridge_id)
            return False
        return True

    def _vrf_l3vni(self, device, rbridge_id, vrf_name, l3vni):
        """ Configure L3VNI on a give VRF """

        try:
            self.logger.info('Configuring l3vni %s on VRF %s on rbridge_id %s', l3vni,
                             vrf_name, rbridge_id)
            l3vni = str(l3vni)
            device.interface.vrf_l3vni(vrf_name=vrf_name, rbridge_id=rbridge_id,
                                       l3vni=l3vni)
        except (ValueError, KeyError):
            self.logger.info('Invalid input types while configuring l3vni %s on VRF %s'
                             ' rbridge_id on %s',
                             l3vni, vrf_name, rbridge_id)
            return False
        return True

    def _vrf_afi_rt_evpn(self, device, rbridge_id, vrf_name, rt, rt_value, afi):
        """Configure Target VPN Extended Communities on a give VRF """

        try:
            self.logger.info('Configuring address-family %s Target VPN %s %s on VRF %s '
                             'on rbridge_id %s',
                             afi, rt, rt_value, vrf_name, rbridge_id)
            device.interface.vrf_afi_rt_evpn(vrf_name=vrf_name, rbridge_id=rbridge_id,
                                             rt=rt, rt_value=rt_value, afi=afi)
        except (ValueError, KeyError):
            self.logger.info('Invalid input types while configuring target VPN on VRF %s '
                             'on rbridge_id %s',
                             vrf_name, rbridge_id)
            return False
        return True

    def _target_vpn_list(self, v4_import, v4_export, v6_import, v6_export):
        """Return a list of the Target VPN Extended Communities on a give VRF """

        v4_rt_list = []
        v4_rt_value_list = []
        v6_rt_list = []
        v6_rt_value_list = []
        ipv4_route_target_import_evpn = v4_import
        ipv4_route_target_export_evpn = v4_export
        ipv6_route_target_import_evpn = v6_import
        ipv6_route_target_export_evpn = v6_export
        if ipv4_route_target_import_evpn != [] and ipv4_route_target_import_evpn is not None:
            rt_type = 'import'
            rt_value = ipv4_route_target_import_evpn
            v4_rt_list.append(rt_type)
            v4_rt_value_list.append(rt_value)
        if ipv4_route_target_export_evpn != [] and ipv4_route_target_export_evpn is not None:
            rt_type = 'export'
            rt_value = ipv4_route_target_export_evpn
            v4_rt_list.append(rt_type)
            v4_rt_value_list.append(rt_value)
        if ipv6_route_target_import_evpn != [] and ipv6_route_target_import_evpn is not None:
            rt_type = 'import'
            rt_value = ipv6_route_target_import_evpn
            v6_rt_list.append(rt_type)
            v6_rt_value_list.append(rt_value)
        if ipv6_route_target_export_evpn != [] and ipv6_route_target_export_evpn is not None:
            rt_type = 'export'
            rt_value = ipv6_route_target_export_evpn
            v6_rt_list.append(rt_type)
            v6_rt_value_list.append(rt_value)

        final_dict = {'v4_rts': v4_rt_list,
                      'v4_rts_value': v4_rt_value_list,
                      'v6_rts': v6_rt_list,
                      'v6_rts_value': v6_rt_value_list}

        return final_dict
