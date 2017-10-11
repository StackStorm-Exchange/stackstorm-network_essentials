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
from ne_base import log_exceptions
import re
import itertools


class ConfigureLogicalInterface(NosDeviceAction):
    """
       Implements the logic to create vlans on VDX and SLX devices.
       This action achieves the below functionality
           1.Configure the logical interface under an interface
           2.Enable untag/tag/double_tag vlan on the logical interface
    """

    def run(self, mgmt_ip, username, password, logical_interface_number, vlan_type,
            intf_type, intf_name, vlan_id, inner_vlan_id):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(logical_interface_number, vlan_type,
                                        vlan_id, inner_vlan_id, intf_type, intf_name)

        return changes

    @log_exceptions
    def switch_operation(self, logical_interface_number, vlan_type,
                         vlan_id, inner_vlan_id, intf_type, intf_name):
        changes = {}
        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info(
                'Successfully connected to %s to configure logical interface',
                self.host)

            self._platform_checks(device, vlan_id, inner_vlan_id, vlan_type)
            lif_name = logical_interface_number.split(',')
            if vlan_id is not None:
                vlan_id = list(itertools.chain.from_iterable(range(int(ranges[0]),
                                  int(ranges[1]) + 1) for ranges in ((el + [el[0]])[:2]
                                  for el in (miniRange.split('-')
                                  for miniRange in vlan_id.split(',')))))
            if inner_vlan_id is not None:
                inner_vlan_id = list(itertools.chain.from_iterable(range(int(ranges[0]),
                                  int(ranges[1]) + 1) for ranges in ((el + [el[0]])[:2]
                                  for el in (miniRange.split('-')
                                  for miniRange in inner_vlan_id.split(',')))))
                
            changes['valid_lif'], lif_list = self._check_interface_presence(device, intf_type,
                                                                            intf_name, lif_name)
            if vlan_type == 'double_tagged':
                changes['valid_vlan'], conf_list = self._check_inner_vlan_id(device,
                                                                             intf_type,
                                                                             intf_name,
                                                                             lif_name,
                                                                             vlan_id,
                                                                             inner_vlan_id)
            elif vlan_type == 'tagged':
                changes['valid_vlan'], conf_list = self._check_vlan_id(device, intf_type,
                                                                       intf_name,
                                                                       lif_name, vlan_id)
            elif vlan_type == 'untagged':
                conf_list = []
                changes['valid_vlan'] = self._check_untag_vlan_id(device, intf_type, intf_name,
                                                                  lif_name, vlan_id)
            if changes['valid_lif']:
                if lif_list != '':
                    changes['lif_create'] = self._logical_interface_create(device, intf_type,
                                                                           intf_name,
                                                                           lif_name=lif_list)
                if changes['lif_create'] and changes['valid_vlan']:
                    if conf_list != [] and vlan_type == 'double_tagged':
                        changes['tag_lif'] = self._dual_tag_lif(device, intf_type, intf_name,
                                                                conf_list)
                    elif vlan_type == 'tagged' and conf_list != []:
                        changes['tag_lif'] = self._single_tag_lif(device, intf_type, intf_name,
                                                                  conf_list)
                    elif vlan_type == 'untagged':
                        changes['untag_lif'] = self._untag_lif(device, intf_type, intf_name,
                                                               lif_name, vlan_id)
            self.logger.info('Closing connection to %s after configuring logical '
                             'interface -- all done!',
                             self.host)
        return changes

    def _platform_checks(self, device, vlan_id, inner_vlan_id, vlan_type):

        if device.os_type == 'nos':
            self.logger.error('Operation is not supported on this device')
            raise ValueError('Operation is not supported on this device')

        pat1 = '\d+r'
        if vlan_type == 'double_tagged' and inner_vlan_id is None or\
                vlan_type == 'double_tagged' and vlan_id is None:
            self.logger.error('vlan_id & inner_vlan_id are mandatory args'
                              ' if vlan_type is double_tagged')
            raise ValueError('vlan_id & inner_vlan_id are mandatory args'
                             ' if vlan_type is double_tagged')
        elif vlan_type == 'tagged' and vlan_id is None:
            self.logger.error('vlan_id is mandatory args'
                              ' if vlan_type is tagged')
            raise ValueError('vlan_id is mandatory args'
                             ' if vlan_type is tagged')
        elif vlan_type == 'untagged' and re.match(pat1, device.firmware_version) and\
                vlan_id is None:
            self.logger.error('vlan_id is mandatory args if vlan_type is untagged'
                              ' on this device')
            raise ValueError('vlan_id is mandatory args if vlan_type is untagged'
                             ' on this device')
        elif vlan_type == 'double_tagged' and not re.match(pat1, device.firmware_version):
            self.logger.error('double_tagged is not support on this device')
            raise ValueError('double_tagged is not support on this device')

    def _check_interface_presence(self, device, intf_type, intf_name, lif_name):

        if intf_type not in device.interface.valid_int_types:
            self.logger.error('Interface type is not valid. '
                              'Interface type must be one of %s'
                              % device.interface.valid_int_types)
            raise ValueError('Interface type is not valid. '
                             'Interface type must be one of %s'
                             % device.interface.valid_int_types)

        if not self.validate_interface(intf_type, intf_name, os_type=device.os_type):
            raise ValueError('Interface %s is not valid' % (intf_name))

        if not device.interface.interface_exists(int_type=intf_type,
                                                 name=intf_name):
            self.logger.error('Interface %s %s is not present on the Device'
                              % (intf_type, intf_name))
            raise ValueError('Interface %s %s is not present on the Device'
                             % (intf_type, intf_name))

        lifs = device.interface.logical_interface_create(get=True, intf_type=intf_type,
                                                         intf_name=intf_name)
        lif_list = lif_name[:]
        if lifs != '':
            for each_lif in lifs:
                if each_lif in lif_name:
                    self.logger.info('lif_name %s is pre-existing on intf_name %s',
                                     each_lif, intf_name)
                    lif_list.remove(each_lif)
        return True, lif_list

    def _check_vlan_id(self, device, intf_type, intf_name, lif_name, vlan_id):
        """ outer vlan id verification """

        tmp = zip(*zip(lif_name, vlan_id))
        tmp_lif = list(tmp[0])[:]
        tmp_vlan = list(tmp[1])[:]
        for lif_name, vlan_id in zip(lif_name, vlan_id):
            dut_untag_vlan = device.interface.logical_interface_untag_vlan(get=True,
                                                     intf_name=intf_name, lif_name=lif_name,
                                                     firmware_version=device.firmware_version,
                                                     intf_type=intf_type)
            if dut_untag_vlan is not None:
                self.logger.info('untag vlan_id %s is pre-existing on lif_name %s',
                                 dut_untag_vlan, lif_name)
                tmp_vlan.remove(dut_untag_vlan)
                tmp_lif.remove(lif_name)
            dut_vlan = device.interface.logical_interface_tag_vlan(get=True, intf_name=intf_name,
                                                                   lif_name=lif_name,
                                                                   intf_type=intf_type)
            if dut_vlan['outer_vlan'] == str(vlan_id):
                self.logger.info('vlan_id %s is pre-existing on lif_name %s', vlan_id, lif_name)
                tmp_vlan.remove(vlan_id)
                tmp_lif.remove(lif_name)
            elif dut_vlan['outer_vlan'] != str(vlan_id) and dut_vlan['outer_vlan'] is not None:
                self.logger.info('lif_name %s is tagged to a different vlan_id %s',
                                 lif_name, dut_vlan['outer_vlan'])
                tmp_vlan.remove(vlan_id)
                tmp_lif.remove(lif_name)
        return True, zip(tmp_lif, tmp_vlan)

    def _check_inner_vlan_id(self, device, intf_type, intf_name, lif_name, vlan_id, inner_vlan_id):
        """ inner vlan id verification """

        tmp = zip(*zip(lif_name, vlan_id, inner_vlan_id))
        tmp_lif = list(tmp[0])[:]
        tmp_vlan = list(tmp[1])[:]
        tmp_in_vlan = list(tmp[2])[:]
        for lif_name, vlan_id, inner_vlan_id in zip(lif_name, vlan_id, inner_vlan_id):
            dut_untag_vlan = device.interface.logical_interface_untag_vlan(get=True,
                                                     intf_name=intf_name, lif_name=lif_name,
                                                     firmware_version=device.firmware_version,
                                                     intf_type=intf_type)
            if dut_untag_vlan is not None:
                self.logger.info('untag vlan_id %s is pre-existing on lif_name %s',
                                 dut_untag_vlan, lif_name)
                tmp_vlan.remove(vlan_id)
                tmp_lif.remove(lif_name)
                tmp_in_vlan.remove(inner_vlan_id)

            dut_vlan = device.interface.logical_interface_tag_vlan(get=True, intf_name=intf_name,
                                                                   lif_name=lif_name,
                                                                   intf_type=intf_type)
            if dut_vlan['outer_vlan'] == str(vlan_id):
                if dut_vlan['inner_vlan'] is not None:
                    if dut_vlan['inner_vlan'] == str(inner_vlan_id):
                        self.logger.info('outer vlan_id %s and inner_vlan_id %s are pre-existing'
                                         ' on lif_name %s', vlan_id, inner_vlan_id, lif_name)
                    if dut_vlan['inner_vlan'] != str(inner_vlan_id):
                        self.logger.info('lif_name %s is tagged to a different inner_vlan_id %s',
                                         lif_name, dut_vlan['inner_vlan'])
                else:
                    self.logger.info('outer vlan_id %s is pre-existing on lif_name %s',
                                     vlan_id, lif_name)
                tmp_vlan.remove(vlan_id)
                tmp_lif.remove(lif_name)
                tmp_in_vlan.remove(inner_vlan_id)
            elif dut_vlan['outer_vlan'] != str(vlan_id) and dut_vlan['outer_vlan'] is not None:
                self.logger.info('lif_name %s is tagged to a different outer vlan_id %s',
                                 lif_name, vlan_id)
                tmp_vlan.remove(vlan_id)
                tmp_lif.remove(lif_name)
                tmp_in_vlan.remove(inner_vlan_id)
        return True, zip(tmp_lif, tmp_vlan, tmp_in_vlan)

    def _check_untag_vlan_id(self, device, intf_type, intf_name, lif_name, vlan_id):
        """ untag vlan id verification """

        switchport_mode = device.interface.trunk_mode(get=True, name=intf_name,
                                                      int_type=intf_type)
        if switchport_mode != 'trunk-no-default-native':
            self.logger.error('Switchport mode must be `trunk-no-default-native` to '
                              'configure untag vlan on a logical interface')
            raise ValueError('Invalid Switchport mode while configuring untag vlan '
                             'on a logical interface')

        lif_name_tmp = lif_name[0]
        dut_tag_vlan = device.interface.logical_interface_tag_vlan(get=True,
                                                                   intf_name=intf_name,
                                                                   lif_name=lif_name_tmp,
                                                                   intf_type=intf_type)
        if dut_tag_vlan['outer_vlan'] is not None:
            self.logger.info('tag vlan_id %s is pre-existing on lif_name %s',
                             dut_tag_vlan['outer_vlan'], lif_name)
            return False

        dut_vlan = device.interface.logical_interface_untag_vlan(get=True,
                                            intf_name=intf_name, lif_name=lif_name[0],
                                            intf_type=intf_type,
                                            firmware_version=device.firmware_version)
        if dut_vlan is not None and vlan_id is not None:
            if dut_vlan == str(vlan_id[0]):
                self.logger.info('untag vlan_id %s is pre-existing on lif_name %s',
                                 vlan_id, lif_name)
                return False
            elif dut_vlan != str(vlan_id[0]):
                self.logger.info('lif_name %s is untagged to a different untag vlan_id %s',
                                 lif_name, dut_vlan)
                return False
        return True

    def _logical_interface_create(self, device, intf_type, intf_name, lif_name):
        """ Configuring logical interface under an interface """

        try:
            for each_lif in lif_name:
                self.logger.info('Configuring lif_name %s under intf_name %s', each_lif, intf_name)
                device.interface.logical_interface_create(intf_type=intf_type,
                                                          intf_name=intf_name,
                                                          lif_name=each_lif)
        except ValueError as e:
                self.logger.exception("Configuring logical interface failed %s"
                                      % (e.message))
                raise ValueError("Configuring logical interface failed")
        return True

    def _dual_tag_lif(self, device, intf_type, intf_name, conf_list):
        """ Configuring dual-tag under a logicalinterface """

        try:
            for lif_name, vlan_id, inner_vlan_id in conf_list:
                self.logger.info('Configuring outer vlan_id %s and inner_vlan_id %s '
                                 'on lif_name %s ',
                                 vlan_id, inner_vlan_id, lif_name)
                device.interface.logical_interface_tag_vlan(intf_type=intf_type,
                                                            outer_tag_vlan_id=vlan_id,
                                                            inner_vlan=True,
                                                            inner_tag_vlan_id=inner_vlan_id,
                                                            intf_name=intf_name,
                                                            lif_name=lif_name)
        except ValueError as e:
            self.logger.exception("Configuring dual-tag on logical interface failed %s"
                                  % (e.message))
            raise ValueError("Configuring dual-tag on logical interface failed")
        return True

    def _single_tag_lif(self, device, intf_type, intf_name, conf_list):
        """ Configuring tag under a logical interface """

        try:
            for each_lif, vlan_id in conf_list:
                self.logger.info('Configuring vlan_id %s on lif_name %s ',
                                 vlan_id, each_lif)
                device.interface.logical_interface_tag_vlan(intf_type=intf_type,
                                                            outer_tag_vlan_id=vlan_id,
                                                            intf_name=intf_name,
                                                            lif_name=each_lif)
        except ValueError as e:
            self.logger.exception("Configuring vlan_id on logical interface failed %s"
                                  % (e.message))
            raise ValueError("Configuring vlan_id on logical interface failed")
        return True

    def _untag_lif(self, device, intf_type, intf_name, lif_name, vlan_id):
        """ Configuring untag under a logical interface """

        try:
            lif_name = lif_name[0]
            if vlan_id is not None:
                vlan_id = vlan_id[0]
            self.logger.info('Configuring untag vlan_id on lif_name %s ', lif_name)
            device.interface.logical_interface_untag_vlan(intf_type=intf_type,
                                                          untag_vlan_id=vlan_id,
                                                          intf_name=intf_name,
                                                          lif_name=lif_name,
                                                          firmware_version=device.firmware_version)
        except ValueError as e:
            self.logger.exception("Configuring untag vlan_id on logical interface failed %s"
                                  % (e.message))
            raise ValueError("Configuring untag vlan_id on logical interface failed")
        return True
