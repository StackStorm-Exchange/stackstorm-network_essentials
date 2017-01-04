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


import re

import ipaddress
import pynos.device
import pynos.utilities
import pyswitchlib.asset
import requests.exceptions
from st2actions.runners.pythonrunner import Action


class NosDeviceAction(Action):

    def __init__(self, config=None, action_service=None):
        super(NosDeviceAction, self).__init__(config=config, action_service=action_service)
        self.result = {'changed': False, 'changes': {}}
        self.mgr = pynos.device.Device
        self.host = None
        self.conn = None
        self.auth = None
        self.asset = pyswitchlib.asset.Asset
        self.RestInterfaceError = pyswitchlib.asset.RestInterfaceError
        self.ConnectionError = requests.exceptions.ConnectionError

    def setup_connection(self, host, user=None, passwd=None):
        self.host = host
        self.conn = (host, '22')
        self.auth = self._get_auth(host=host, user=user, passwd=passwd)

    def _get_auth(self, host, user, passwd):
        if not user:
            lookup_key = self._get_lookup_key(host=self.host, lookup='user')
            user_kv = self.action_service.get_value(name=lookup_key, local=False)
            if not user_kv:
                raise Exception('username for %s not found.' % host)
            user = user_kv
        if not passwd:
            lookup_key = self._get_lookup_key(host=self.host, lookup='passwd')
            passwd_kv = self.action_service.get_value(name=lookup_key, local=False, decrypt=True)
            if not passwd_kv:
                raise Exception('password for %s not found.' % host)
            passwd = passwd_kv
        return (user, passwd)

    def _get_lookup_key(self, host, lookup):
        return 'switch.%s.%s' % (host, lookup)

    def check_int_description(self, intf_description):
        """
        Check for valid interface description
        """
        err_code = len(intf_description)
        if err_code < 1:
            self.logger.info('Pls specify a valid description')
            return False
        elif err_code <= 63:
            return True
        else:
            self.logger.info('Length of the description is more than the allowed size')
            return False

    def expand_vlan_range(self, vlan_id):
        """Fail the task if vlan id is zero or one or above 4096 .
        """

        re_pattern1 = r"^(\d+)$"
        re_pattern2 = r"^(\d+)\-?(\d+)$"

        if re.search(re_pattern1, vlan_id):
            try:
                vlan_id = (int(vlan_id),)
            except ValueError:
                self.logger.info("Could not convert data to an integer.")
                return None
        elif re.search(re_pattern2, vlan_id):
            try:
                vlan_id = re.match(re_pattern2, vlan_id)
            except ValueError:
                self.logger.info("Not in valid range format.")
                return None

            if int(vlan_id.groups()[0]) == int(vlan_id.groups()[1]):
                self.logger.warning("Use range command only for diff vlans")
            vlan_id = range(int(vlan_id.groups()[0]), int(vlan_id.groups()[1]) + 1)

        else:
            self.logger.info("Invalid vlan format")
            return None

        for vid in vlan_id:
            if vid > 4096:
                extended = "true"
            else:
                extended = "false"

            tmp_vlan_id = pynos.utilities.valid_vlan_id(vid, extended=extended)

            reserved_vlan_list = range(4087, 4096)
            reserved_vlan_list.append(1002)

            if not tmp_vlan_id:
                self.logger.info("'Not a valid VLAN %s", vid)
                return None
            if vid == 1:
                self.logger.info("vlan %s is default vlan", vid)
                return None
            elif vid in reserved_vlan_list:
                self.logger.info("Vlan cannot be created, as it is not a user/fcoe vlan %s", vid)
                return None

        return vlan_id

    def expand_interface_range(self, intf_type, intf_name, rbridge_id):
        msg = None

        int_list = intf_name
        re_pattern1 = r"^(\d+)$"
        re_pattern2 = r"^(\d+)\-?(\d+)$"
        re_pattern3 = r"^(\d+)\/(\d+)\/(\d+)$"
        re_pattern4 = r"^(\d+)\/(\d+)\/(\d+)\-?(\d+)$"

        intTypes = ["port_channel", "gigabitethernet", "tengigabitethernet", "fortygigabitethernet",
                    "hundredgigabitethernet"]
        if rbridge_id is None and 'loopback' in intf_type:
            msg = 'Must specify `rbridge_id` when specifying a `loopback`'
        elif rbridge_id is None and 've' in intf_type:
            msg = 'Must specify `rbridge_id` when specifying a `ve`'
        elif rbridge_id is not None and intf_type in intTypes:
            msg = 'Should not specify `rbridge_id` when specifying a ' + intf_type
        elif re.search(re_pattern1, int_list):
            int_list = ((int_list),)
        elif re.search(re_pattern2, int_list):
            try:
                int_list = re.match(re_pattern2, int_list)
            except Exception:
                return None

            if int(int_list.groups()[0]) == int(int_list.groups()[1]):
                self.logger.info("Use range command only for unique values")
            int_list = range(int(int_list.groups()[0]), int(int_list.groups()[1]) + 1)
        elif re.search(re_pattern3, int_list):
            int_list = ((int_list),)
        elif re.search(re_pattern4, int_list):
            try:
                temp_list = re.match(re_pattern4, int_list)
            except Exception:
                return None

            if int(temp_list.groups()[0]) == int(temp_list.groups()[1]):
                self.logger.info("Use range command only for unique values")
            intList = range(int(temp_list.groups()[2]), int(temp_list.groups()[3]) + 1)
            int_list = []
            for intf in intList:
                int_list.append(temp_list.groups()[0] + '/' + temp_list.groups()[1] + '/' +
                                str(intf))
            int_list = int_list
        else:
            msg = 'Invalid interface format'

        if msg is not None:
            self.logger.info(msg)
            return None

        for intf in int_list:
            intTypes = ["ve", "loopback"]
            if intf_type not in intTypes:
                tmp_vlan_id = pynos.utilities.valid_interface(intf_type, name=str(intf))

                if not tmp_vlan_id:
                    self.logger.info("Not a valid interface type %s or name %s", intf_type, intf)
                    return None

        return int_list

    @staticmethod
    def is_valid_mac(mac):
        """
        This will only validate the HHHH.HHHH.HHHH MAC format. Will need to be expanded to
        validate other formats of MAC.

        :param mac:
        :return:
        """
        if re.match('[0-9A-Fa-f]{4}[.][0-9A-Fa-f]{4}[.][0-9A-Fa-f]{4}$', mac):
            return True
        else:
            return False

    @staticmethod
    def is_valid_ip(ip):
        try:
            ipaddress.ip_address(ip.decode('utf-8'))
            return True
        except ValueError:
            return False
        except AttributeError:
            return False

    @staticmethod
    def mac_converter(old_mac):
        """
        This method converts MAC from xxxx.xxxx.xxxx to xx:xx:xx:xx:xx:xx. This
        helps provide consistency across persisting MACs in the DB.

        Args:
                old_mac: MAC in a format xxxx.xxxx.xxxx

            Returns:
                dict: updated MAC in the xx:xx:xx:xx:xx:xx format
        """
        new_mac = old_mac.replace('.', '')
        newer_mac = ':'.join([new_mac[i:i + 2] for i in range(0, len(new_mac), 2)])
        return newer_mac

    def get_rbridge_id(self, intf_name):
        """
        This method fetches rbridge_id from single interface name.This
        helps user not to pass the rbridge_id as input.

        Args:
                intf_name: Name of the interface

            Returns:
                rbridge_id: rbridge id of the interface
        """

        re_pattern1 = r"^(\d+)\/(\d+)\/(\d+)$"

        if not intf_name:
            self.logger.info('Input for `intf_name` is empty')
            return False
        elif re.search(re_pattern1, intf_name):
            try:
                intf_name = re.match(re_pattern1, intf_name)
            except Exception:
                return False

            rbridge_id = int(intf_name.groups()[0])
            if rbridge_id < 1 or rbridge_id > 239:
                self.logger.info('Invalid Rbridge_id %s', rbridge_id)
                return False
        else:
            self.logger.info('Invalid Interface Name %s', intf_name)
            return False

        return rbridge_id

    def _get_acl_type_(self, device, acl_name):
        acl_type = {}
        try:
            get = device.ip_access_list_standard_get(acl_name)
            acl_type['type'] = str(get[1][0][self.host]['response']['json']['output'].keys()[0])
            acl_type['protocol'] = 'ip'
            return acl_type
        except:
            pass
        try:
            get = device.ip_access_list_extended_get(acl_name)
            acl_type['type'] = str(get[1][0][self.host]['response']['json']['output'].keys()[0])
            acl_type['protocol'] = 'ip'
            return acl_type
        except:
            pass
        try:
            get = device.mac_access_list_standard_get(acl_name)
            acl_type['type'] = str(get[1][0][self.host]['response']['json']['output'].keys()[0])
            acl_type['protocol'] = 'mac'
            return acl_type
        except:
            pass
        try:
            get = device.mac_access_list_extended_get(acl_name)
            acl_type['type'] = str(get[1][0][self.host]['response']['json']['output'].keys()[0])
            acl_type['protocol'] = 'mac'
            return acl_type
        except:
            pass
        try:
            get = device.ipv6_access_list_standard_get(acl_name)
            acl_type['type'] = str(get[1][0][self.host]['response']['json']['output'].keys()[0])
            acl_type['protocol'] = 'ipv6'
            return acl_type
        except:
            pass
        try:
            get = device.ipv6_access_list_extended_get(acl_name)
            acl_type['type'] = str(get[1][0][self.host]['response']['json']['output'].keys()[0])
            acl_type['protocol'] = 'ipv6'
            return acl_type
        except:
            self.logger.info('Cannot get acl-type for  %s', acl_name)
            return None

    def _get_seq_(self, device, acl_name, acl_type, seq_id):

        get = device.ip_access_list_extended_get if acl_type == 'extended' else \
            device.ip_access_list_standard_get

        try:
            get_output = get(acl_name, resource_depth=3)
            acl_dict = get_output[1][0][self.host]['response']['json']['output'][acl_type]
            if 'seq' in acl_dict:
                seq_list = acl_dict['seq']
                seq_list = seq_list if type(seq_list) == list else [seq_list, ]
                for seq in seq_list:
                    if seq['seq-id'] == str(seq_id):
                        return seq
            else:
                self.logger.info('No seq present in acl %s', acl_name)
                return None

        except:
            self.logger.info('cannot get seq in acl %s', acl_name)
            return None

    def _get_port_channel_members(self, device, portchannel_num):
        members = []
        results = []
        port_channel_exist = False
        keys = ['interface-type', 'rbridge-id', 'interface-name', 'sync']
        port_channel_get = self._get_port_channels(device)
        if port_channel_get:
            for port_channel in port_channel_get:
                if port_channel['aggregator-id'] == str(portchannel_num):
                    port_channel_exist = True
                    if 'aggr-member' in port_channel:
                        members = port_channel['aggr-member']
                    else:
                        self.logger.info('Port Channel %s does not have any members',
                                         str(portchannel_num))
                        return results
        else:
            return None
        get = device.get_port_channel_detail_rpc()
        output = get[1][0][self.host]['response']['json']['output']
        if 'lacp' in output:
            port_channel_get = output['lacp']
        else:
            self.logger.info(
                'Port Channel is not configured on the device')
            return None
        if type(port_channel_get) == dict:
            port_channel_get = [port_channel_get, ]
        for port_channel in port_channel_get:
            print port_channel
            if port_channel['aggregator-id'] == str(portchannel_num):
                port_channel_exist = True
                if 'aggr-member' in port_channel:
                    members = port_channel['aggr-member']
                else:
                    self.logger.info('Port Channel %s does not have any members',
                                     str(portchannel_num))
                    return results
        if not port_channel_exist:
            self.logger.info('Port Channel %s is not configured on the device',
                             str(portchannel_num))
            return results

        if type(members) == dict:
            members = [members, ]
        for member in members:
            result = {}
            for key, value in member.iteritems():
                if key in keys:
                    result[key] = value
            results.append(result)
        return results

    def _get_port_channels(self, device):
        connected = False
        for _ in range(5):
            get = device.get_port_channel_detail_rpc()
            if get[0]:
                output = get[1][0][self.host]['response']['json']['output']
                connected = True
                break
        if not connected:
            self.logger.error(
                'Cannot get Port Channels')
            raise self.ConnectionError(get[1][0][self.host]['response']['json']['output'])
        if 'lacp' in output:
            port_channel_get = output['lacp']
        else:
            self.logger.info(
                'Port Channel is not configured on the device')
            return None
        if type(port_channel_get) == dict:
            port_channel_get = [port_channel_get, ]
        return port_channel_get
