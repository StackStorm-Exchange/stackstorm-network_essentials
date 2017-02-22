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
import pyswitch.device
import pynos.utilities
import pyswitchlib.asset
import requests.exceptions
import socket
from st2actions.runners.pythonrunner import Action


class NosDeviceAction(Action):

    def __init__(self, config=None, action_service=None):
        super(
            NosDeviceAction,
            self).__init__(
            config=config,
            action_service=action_service)
        self.result = {'changed': False, 'changes': {}}
        self.mgr = pynos.device.Device
        self.pmgr = pyswitch.device.Device
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
            user_kv = self.action_service.get_value(
                name=lookup_key, local=False)
            if not user_kv:
                raise Exception('username for %s not found.' % host)
            user = user_kv
        if not passwd:
            lookup_key = self._get_lookup_key(host=self.host, lookup='passwd')
            passwd_kv = self.action_service.get_value(
                name=lookup_key, local=False, decrypt=True)
            if not passwd_kv:
                raise Exception('password for %s not found.' % host)
            passwd = passwd_kv
        return (user, passwd)

    def _get_lookup_key(self, host, lookup):
        return 'switch.%s.%s' % (host, lookup)

    def get_device(self):
        try:
            device = self.asset(ip_addr=self.host, auth=self.auth)
            self.logger.info('successfully connected to %s',
                             self.host)
            return device
        except AttributeError as e:
            self.logger.error("Failed to connect to %s due to %s",
                              self.host, e.message)
            raise self.ConnectionError(
                'Failed to connect to %s due to %s', self.host, e.message)
        except ValueError as verr:
            self.logger.error("Error while logging in to %s due to %s",
                              self.host, verr.message)
            raise self.ConnectionError("Error while logging in to %s due to %s",
                                       self.host, verr.message)
        except IndexError as ierr:
            self.logger.error("Error while logging in to %s due to wrong Username/Password",
                              self.host)
            raise self.ConnectionError("Error while logging in to %s due to %s",
                                       self.host, ierr.message)
        except self.ConnectionError as cerr:
            self.logger.error("Connection failed while logging in to %s due to %s",
                              self.host, cerr.message)
            raise self.ConnectionError("Connection failed while logging in to %s due to %s",
                                       self.host, cerr.message)
        except self.RestInterfaceError as rierr:
            self.logger.error("Failed to get a REST response while logging in "
                              "to %s due to %s", self.host, rierr.message)
            raise self.ConnectionError("Failed to get a REST response while logging in "
                                       "to %s due to %s", self.host, rierr.message)

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
            self.logger.info(
                'Length of the description is more than the allowed size')
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
            vlan_id = range(int(vlan_id.groups()[0]), int(
                vlan_id.groups()[1]) + 1)

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

            if not tmp_vlan_id:
                self.logger.error("'Not a valid vlan %s", vid)
                return None
            elif vid in reserved_vlan_list:
                self.logger.error(
                    "Vlan cannot be created, as it is not a user/fcoe vlan %s", vid)
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
            int_list = range(int(int_list.groups()[0]), int(
                int_list.groups()[1]) + 1)
        elif re.search(re_pattern3, int_list):
            int_list = ((int_list),)
        elif re.search(re_pattern4, int_list):
            try:
                temp_list = re.match(re_pattern4, int_list)
            except Exception:
                return None

            if int(temp_list.groups()[0]) == int(temp_list.groups()[1]):
                self.logger.info("Use range command only for unique values")
            intList = range(int(temp_list.groups()[2]), int(
                temp_list.groups()[3]) + 1)
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
                tmp_vlan_id = pynos.utilities.valid_interface(
                    intf_type, name=str(intf))

                if not tmp_vlan_id:
                    self.logger.info(
                        "Not a valid interface type %s or name %s", intf_type, intf)
                    return None

        return int_list

    def extend_interface_range(self, intf_type, intf_name):
        msg = None

        int_list = intf_name
        re_pattern1 = r"^(\d+)\-?(\d+)$"
        re_pattern2 = r"^(\d+)\/(\d+)\-?(\d+)$"
        re_pattern3 = r"^(\d+)\/(\d+)\/(\d+)\-?(\d+)$"

        if re.search(re_pattern1, int_list):
            try:
                int_list = re.match(re_pattern1, int_list)
            except Exception:
                return None

            if int(int_list.groups()[0]) == int(int_list.groups()[1]):
                self.logger.info("Use range command only for unique values")
            int_list = range(int(int_list.groups()[0]), int(
                int_list.groups()[1]) + 1)

        elif re.search(re_pattern2, int_list):
            try:
                temp_list = re.match(re_pattern2, int_list)
            except Exception:
                return None

            if int(temp_list.groups()[1]) == int(temp_list.groups()[2]):
                self.logger.info("Use range command only for unique values")
            intList = range(int(temp_list.groups()[1]), int(
                temp_list.groups()[2]) + 1)
            int_list = []
            for intf in intList:
                int_list.append(temp_list.groups()[0] + '/' + str(intf))
            int_list = int_list

        elif re.search(re_pattern3, int_list):
            try:
                temp_list = re.match(re_pattern3, int_list)
            except Exception:
                return None

            if int(temp_list.groups()[2]) == int(temp_list.groups()[3]):
                self.logger.info("Use range command only for unique values")
            intList = range(int(temp_list.groups()[2]), int(
                temp_list.groups()[3]) + 1)
            int_list = []
            for intf in intList:
                int_list.append(temp_list.groups()[0] + '/' + temp_list.groups()[1] + '/' +
                                str(intf))
            int_list = int_list
        else:
            msg = 'Invalid interface format'

        if msg is not None:
            self.logger.error(msg)
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
        newer_mac = ':'.join([new_mac[i:i + 2]
                              for i in range(0, len(new_mac), 2)])
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

    def _validate_ip_(self, addr):
        try:
            socket.inet_aton(addr)
            return True
        except socket.error:
            return False

    def _validate_ipv6_(self, addr):
        try:
            socket.inet_pton(socket.AF_INET6, addr)
            return True
        except socket.error:
            return False

    def validate_interface(self, intf_type, intf_name, rbridge_id=None):
        msg = None
        # int_list = intf_name
        re_pattern1 = r"^(\d+)$"
        re_pattern2 = r"^(\d+)\/(\d+)\/(\d+)(:(\d+))?$"
        re_pattern3 = r"^(\d+)\/(\d+)(:(\d+))?$"
        intTypes = ["port_channel", "gigabitethernet", "tengigabitethernet",
                    "fortygigabitethernet", "hundredgigabitethernet", "ethernet"]
        NosIntTypes = [
            "gigabitethernet",
            "tengigabitethernet",
            "fortygigabitethernet"]
        if rbridge_id is None and 'loopback' in intf_type:
            msg = 'Must specify `rbridge_id` when specifying a `loopback`'
        elif rbridge_id is None and 've' in intf_type:
            msg = 'Must specify `rbridge_id` when specifying a `ve`'
        elif rbridge_id is not None and intf_type in intTypes:
            msg = 'Should not specify `rbridge_id` when specifying a ' + intf_type
        elif re.search(re_pattern1, intf_name):
            intf = intf_name
        elif re.search(re_pattern2, intf_name) and intf_type in NosIntTypes:
            intf = intf_name
        elif re.search(re_pattern3, intf_name) and 'ethernet' in intf_type:
            intf = intf_name
        else:
            msg = 'Invalid interface format'

        if msg is not None:
            self.logger.error(msg)
            return False

        intTypes = ["ve", "loopback", "ethernet"]
        if intf_type not in intTypes:
            tmp_vlan_id = pynos.utilities.valid_interface(
                intf_type, name=str(intf))

            if not tmp_vlan_id:
                self.logger.error(
                    "Not a valid interface type %s or name %s", intf_type, intf)
                return False

        return True

    def _get_acl_type_(self, device, acl_name):
        acl_type = {}
        try:
            get = device.ip_access_list_standard_get(acl_name)
            acl_type['type'] = str(get[1][0][self.host]['response'][
                                   'json']['output'].keys()[0])
            acl_type['protocol'] = 'ip'
            return acl_type
        except:
            pass
        try:
            get = device.ip_access_list_extended_get(acl_name)
            acl_type['type'] = str(get[1][0][self.host]['response'][
                                   'json']['output'].keys()[0])
            acl_type['protocol'] = 'ip'
            return acl_type
        except:
            pass
        try:
            get = device.mac_access_list_standard_get(acl_name)
            acl_type['type'] = str(get[1][0][self.host]['response'][
                                   'json']['output'].keys()[0])
            acl_type['protocol'] = 'mac'
            return acl_type
        except:
            pass
        try:
            get = device.mac_access_list_extended_get(acl_name)
            acl_type['type'] = str(get[1][0][self.host]['response'][
                                   'json']['output'].keys()[0])
            acl_type['protocol'] = 'mac'
            return acl_type
        except:
            pass
        try:
            get = device.ipv6_access_list_standard_get(acl_name)
            acl_type['type'] = str(get[1][0][self.host]['response'][
                                   'json']['output'].keys()[0])
            acl_type['protocol'] = 'ipv6'
            return acl_type
        except:
            pass
        try:
            get = device.ipv6_access_list_extended_get(acl_name)
            acl_type['type'] = str(get[1][0][self.host]['response'][
                                   'json']['output'].keys()[0])
            acl_type['protocol'] = 'ipv6'
            return acl_type
        except:
            self.logger.error('Cannot get acl-type for  %s', acl_name)
            return None

    def _get_seq_id_(self, device, acl_name, acl_type, ip_type=None):
        if ip_type is None:
            get = device.ip_access_list_extended_get if acl_type == 'extended' else \
                device.ip_access_list_standard_get
        elif ip_type == 'ipv6':
            get = device.ipv6_access_list_extended_get if acl_type == 'extended' else \
                device.ipv6_access_list_standard_get
        elif ip_type == 'mac':
            get = device.mac_access_list_extended_get if acl_type == 'extended' else \
                device.mac_access_list_standard_get
        try:
            get_output = get(acl_name)[1][0][
                self.host]['response']['json']['output']
            if acl_type in get_output:
                acl_dict = get_output[acl_type]
            else:
                self.logger.error(
                    '%s access list %s does not exist', acl_type, acl_name)
                return None
            if 'seq' in acl_dict:
                seq_list = acl_dict['seq']
                if isinstance(seq_list, list):
                    last_seq_id = int(seq_list[len(seq_list) - 1]['seq-id'])
                else:
                    last_seq_id = int(seq_list['seq-id'])
                if last_seq_id % 10 == 0:  # divisible by 10
                    seq_id = last_seq_id + 10
                else:
                    # rounding up to the nearest 10
                    seq_id = (last_seq_id + 9) // 10 * 10
            else:
                seq_id = 10
            return seq_id
        except KeyError:
            return None

    def _get_seq_(self, device, acl_name, acl_type, seq_id, address_type=None):
        if address_type == 'ipv6':
            get = device.ipv6_access_list_extended_get if acl_type == 'extended' else \
                device.ipv6_access_list_standard_get
        elif address_type == 'mac':
            get = device.mac_access_list_extended_get if acl_type == 'extended' else \
                device.mac_access_list_standard_get
        else:
            get = device.ip_access_list_extended_get if acl_type == 'extended' else \
                device.ip_access_list_standard_get

        try:
            get_output = get(acl_name, resource_depth=3)
            acl_dict = get_output[1][0][self.host][
                'response']['json']['output'][acl_type]
            if 'seq' in acl_dict:
                seq_list = acl_dict['seq']
                seq_list = seq_list if isinstance(
                    seq_list, list) else [seq_list, ]
                for seq in seq_list:
                    if seq['seq-id'] == str(seq_id):
                        return seq
            else:
                self.logger.error('No seq present in acl %s', acl_name)
                return None

        except:
            self.logger.error('cannot get seq in acl %s', acl_name)
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
        if not port_channel_exist:
            self.logger.info('Port Channel %s is not configured on the device',
                             str(portchannel_num))
            return results

        if isinstance(members, dict):
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
            raise self.ConnectionError(
                get[1][0][self.host]['response']['json']['output'])
        if 'lacp' in output:
            port_channel_get = output['lacp']
        else:
            self.logger.info(
                'Port Channel is not configured on the device')
            return None
        if isinstance(port_channel_get, dict):
            port_channel_get = [port_channel_get, ]
        return port_channel_get

    def _get_switchport(self, device):
        connected = False
        for _ in range(5):
            get = device.get_interface_switchport_rpc()
            if get[0]:
                output = get[1][0][self.host]['response']['json']['output']
                connected = True
                break
        if not connected:
            self.logger.error(
                'Cannot get switchport')
            raise self.ConnectionError(
                get[1][0][self.host]['response']['json']['output'])
        if 'switchport' in output:
            switchport_get = output['switchport']
        else:
            self.logger.info(
                'Switchport is not configured on the device')
            return None
        if isinstance(switchport_get, dict):
            switchport_get = [switchport_get, ]
        return switchport_get

    def _interface_update(self, device, intf_type, intf_name,
                          ifindex=None, description=None, shutdown=None, mtu=None):
        if intf_type == 'ethernet':
            update = device.interface_ethernet_update
        elif intf_type == 'gigabitethernet':
            update = device.interface_gigabitethernet_update
        elif intf_type == 'tengigabitethernet':
            update = device.interface_tengigabitethernet_update
        elif intf_type == 'fortygigabitethernet':
            update = device.interface_fortygigabitethernet_update
        elif intf_type == 'hundredgigabitethernet':
            update = device.interface_hundredgigabitethernet_update
        elif intf_type == 'port-channel':
            update = device.interface_port_channel_update
        else:
            self.logger.error('intf_type %s is not supported',
                              intf_type)
            return False

        try:
            result = update(intf_name, ifindex=ifindex,
                            description=description, shutdown=shutdown,
                            mtu=mtu)
            if result[0]:
                self.logger.info('Updating %s %s interface is done',
                                 intf_type, intf_name)
                return True
            else:
                self.logger.error('Updating %s %s interface failed because %s',
                                  intf_type, intf_name,
                                  result[1][0][self.host]['response']['json']['output'])
                return False

        except (TypeError, AttributeError, ValueError) as e:
            self.logger.error('Interface update failed because %s', e.message)
            return False

    def _get_interface_admin_state(self, device, intf_type, intf_name):
        last_rcvd_interface = None
        while True:
            admin_state = None
            connected = False
            for _ in range(5):
                get = device.get_interface_detail_rpc(
                    last_rcvd_interface=last_rcvd_interface)
                if get[0]:
                    output = get[1][0][self.host]['response']['json']['output']
                    connected = True
                    break
            if not connected:
                self.logger.error(
                    'Cannot get interface details')
                raise self.ConnectionError()
            if 'interface' in output:
                intf_dict = output['interface']
                if isinstance(intf_dict, dict):
                    intf_dict = [intf_dict, ]
                for out in intf_dict:
                    if intf_name in out[
                            'if-name'] and intf_type == out['interface-type']:
                        admin_state = out['line-protocol-state']
                        return admin_state
                last_rcvd_interface = (
                    out['interface-type'], out['interface-name'])
                if output['has-more']:
                    continue
            else:
                self.logger.info("No interfaces found in host %s", self.host)
                return admin_state

    def _get_os_type(self, device):
        os_name = None
        try:
            get = device.show_firmware_version_rpc()[1][0][
                self.host]['response']['json']['output']['show-firmware-version']['os-name']
            if 'Network' in get:
                os_name = 'NOS'
            elif 'SLX' in get:
                os_name = 'SLX-OS'
        except (TypeError, KeyError, AttributeError):
            self.logger.error("Cannot get OS version")
        return os_name

    def _get_interface_address(
            self, device, intf_type, intf_name, ip_version, rbridge_id=None):
        if ip_version == 4:
            ip = 'ip'
        elif ip_version == 6:
            ip = 'ipv6'
        method = 'rbridge_id_interface_{}_get'. \
            format(intf_type) if rbridge_id \
            else 'interface_{}_get'.format(intf_type)
        get_intf = eval('device.{}'.format(method))
        get = get_intf(
            rbridge_id,
            intf_name) if rbridge_id else get_intf(intf_name)
        if get[0]:
            output = get[1][0][self.host]['response']['json']['output']
        else:
            return None
        if output is not None:
            ip_intf = output.itervalues().next()[ip]
            while True:
                if 'address' not in ip_intf:
                    try:
                        ip_intf = ip_intf.pop()
                    except:
                        return None
                else:
                    ip_intf = ip_intf['address']
                    break
            if ip == 'ip':
                while True:
                    if 'address' not in ip_intf:
                        try:
                            ip_intf = ip_intf.pop()
                        except:
                            return None
                    else:
                        return ip_intf['address']
            elif ip == 'ipv6':
                while True:
                    if 'ipv6-address' not in ip_intf:
                        try:
                            ip_intf = ip_intf.pop()
                        except:
                            return None
                    else:
                        ip_intf = ip_intf['ipv6-address']
                        break
                while True:
                    if 'address' not in ip_intf:
                        try:
                            ip_intf = ip_intf.pop()
                        except:
                            return None
                    else:
                        return ip_intf['address']
        else:
            return None

    def _get_ip_intf(self, device, intf_type=None):
        connected = False
        for _ in range(5):
            get = device.get_ip_interface_rpc()
            if get[0]:
                output = get[1][0][self.host]['response']['json']['output']
                connected = True
                break
        if not connected:
            self.logger.error(
                'Cannot get interface details')
            raise self.ConnectionError(
                get[1][0][self.host]['response']['json']['output'])
        if 'interface' in output:
            ip_intf = output['interface']
            if isinstance(ip_intf, dict):
                ip_intf = [ip_intf, ]
        else:
            self.logger.info("No interfaces found in host %s", self.host)
            return None
        if intf_type is None:
            return [x['if-name'] for x in ip_intf]
        else:
            return [x['if-name']
                    for x in ip_intf if intf_type in x['if-name'].lower()]

    def vlag_pair(self, device):
        """ Fetch the RB list if VLAG is configured"""
        rb_list = []
        result = device.vcs.vcs_nodes
        for each_rb in result:
            if each_rb['node-status'] == 'Co-ordinator' or each_rb['node-status'] == 'Connected ' \
                                                                                     'to Cluster':
                rb_list.append(each_rb['node-rbridge-id'])
        if len(rb_list) >= 3:
            raise ValueError('VLAG PAIR must be <= 2 leaf nodes')
        return list(set(rb_list))

    def extract_port_list(self, intf_type, port_list):
        interface_list = []
        for intf in port_list:
            if "-" not in str(intf):
                interface_list.append(str(intf))
            else:
                ex_intflist = self.extend_interface_range(intf_type=intf_type,
                                                          intf_name=intf)
                for ex_intf in ex_intflist:
                    interface_list.append(str(ex_intf))

        for intf in interface_list:
            if not self.validate_interface(intf_type, intf):
                msg = "Input is not a valid Interface"
                self.logger.error(msg)
                raise ValueError(msg)
        return interface_list

    def validate_supports_rbridge(self, device, rbridge_id):
        if device.suports_rbridge:
            if rbridge_id is None:
                self.logger.info('Device requires rbridge-id')
                raise ValueError('Device requires rbridge-id')
            return True
        if rbridge_id is not None:
            self.logger.info('Device does not support rbridge')
            raise ValueError('Device does not support rbridge')

# log_exceptions decorator


def log_exceptions(func):
    def wrapper(*args, **kwds):
        logger = args[0].logger
        host = args[0].host
        try:
            return func(*args, **kwds)
        except AttributeError as e:
            logger.exception(
                'Failed to connect to %s due to %s'
                % (host,
                   e.message))
            raise
        except ValueError as verr:
            logger.exception("Error encountered on %s due to %s"
                             % (host, verr.message))
            raise
        except requests.exceptions.ConnectionError as cerr:
            logger.exception("Connection failed while logging in to %s "
                             "due to %s"
                             % (host, cerr.message.reason))
            raise
        except pyswitchlib.asset.RestInterfaceError as rierr:
            logger.exception(
                "Failed to get a REST response on "
                "%s due to %s" % (host, rierr.message))
            raise
        except Exception as ex:
            logger.exception(
                "Error while logging in to %s due to %s"
                % (host, ex.message))
            raise

    return wrapper

    def check_status_code(self, operation, device_ip):
        status_code = operation[1][0][device_ip]['response']['status_code']
        self.logger.debug("Operation returned %s", status_code)
        if status_code >= 400:
            error_msg = operation[1][0][device_ip]['response']['text']
            self.logger.debug(
                "REST Operation failed with status code %s",
                status_code)
            raise ValueError(error_msg)
