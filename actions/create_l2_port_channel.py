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

import pyswitch.utilities
import sys
import re
import random
from execute_cli import CliCMD
from ne_base import NosDeviceAction


class CreatePortChannel(NosDeviceAction):
    """
       Implements the logic to create port-channel on an interface on VDX Switches .
       This action acheives the below functionality
           1.Create a port channel
           2.Configure the mode, group
           3.Admin up the interface and port-channel
           4.Fabric isl,trunk and neighbor-discovery settings
    """

    def run(self, mgmt_ip, username, password, ports, intf_type, port_channel_id,
           protocol, mode, port_channel_desc):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}
        if protocol == "modeon":
            protocol = "on"

        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info('successfully connected to %s to create port channel', self.host)
            if device.os_type == 'slxos':
                if mode != "standard":
                    self.logger.error('SLXOS only supports port-channel type as standard')
                    sys.exit(-1)
            if device.os_type == 'NI':
                if mode != "standard":
                    self.logger.error('MLX only supports port-channel type as standard')
                    sys.exit(-1)
                if protocol == "on":
                    protocol = "static"
                elif protocol == "active":
                    protocol = "dynamic"
                else:
                    self.logger.error('NI/MLX doesnt support port-channel protocol %s', protocol)
                    sys.exit(-1)

            changes['pre_validation'] = self._check_requirements(device, ports, intf_type,
                                                                 port_channel_id,
                                                                 port_channel_desc)
            if changes['pre_validation']:
                if device.os_type == 'NI':
                    changes['port_channel_configs'] = self._create_port_channel_mlx(device,
                                                              intf_name=ports,
                                                              intf_type=intf_type,
                                                              portchannel_num=port_channel_id,
                                                              channel_type=mode,
                                                              mode_type=protocol,
                                                              intf_desc=port_channel_desc)
                else:
                    changes['port_channel_configs'] = self._create_port_channel(device,
                                                              intf_name=ports,
                                                              intf_type=intf_type,
                                                              portchannel_num=port_channel_id,
                                                              channel_type=mode,
                                                              mode_type=protocol,
                                                              intf_desc=port_channel_desc)
            self.logger.info('intf_type {0} ports {1}'.format(intf_type, ports))
            if device.os_type == 'nos':
                changes['fabric_isl_disable'] = self._disable_isl(device, intf_type, ports)
                changes['fabric_trunk_disable'] = self._disable_trunk(device, intf_type, ports)
                changes['fabric_neighbor_discovery'] = self._fabric_neighbor(device,
                                                            intf_type, ports)
            self.logger.info('closing connection to %s after'
                             ' configuring port channel -- all done!', self.host)
        return changes

    def _check_requirements(self, device, intf_name, intf_type, portchannel_num, intf_desc):
        """ Verify if the port channel already exists """
        for each in intf_name:
            r1 = pyswitch.utilities.valid_interface(int_type=intf_type, name=each)
            if not r1:
                raise ValueError('Not a valid interface type or number', intf_type, each)

        r2 = pyswitch.utilities.valid_interface(int_type='port_channel', name=portchannel_num)
        if not r2:
            raise ValueError('Port Channel number %s is not a valid value', portchannel_num)

        valid_desc = True
        if intf_desc:
            valid_desc = self.check_int_description(intf_description=intf_desc)
            if not valid_desc:
                raise ValueError('Invalid interface description %s', intf_desc)
        else:
            if device.os_type == 'NI':
                raise ValueError('Port-channel name/description cannot be NULL for MLX %d',
                        portchannel_num)

        result = device.interface.port_channels
        tmp1 = "-" + portchannel_num
        port_chan = "port-channel" + tmp1
        # For NI/MLX Portchannel name/descr is mandatory
        if device.os_type == 'NI':
            port_chan = intf_desc

        # Verify if the port channel to interface mapping is already existing
        for port_chann in result:
            if port_chann['interface-name'] == port_chan:
                if port_chann['aggregator_type'] == 'standard':
                    for interfaces in port_chann['interfaces']:
                        if interfaces['interface-name'] in intf_name:
                            self.logger.info(
                                'Port Channel %s to interface %s mapping is'
                                ' pre-existing',
                                portchannel_num, interfaces['interface-name'])
                            return False
            else:
                for interfaces in port_chann['interfaces']:
                    if interfaces['interface-name'] in intf_name:
                        self.logger.info('Interface %s is already mapped to a'
                                         ' different port channel %s',
                                         interfaces['interface-name'], port_chann['interface-name'])
                        return False
        return True

    def _create_port_channel(self, device, intf_name, intf_type, portchannel_num,
                             channel_type, mode_type, intf_desc):
        """ Configuring the port channel and channel-group,
            Admin state up on interface and port-channel."""
        actual_line_speed = False
        po_speed = None
        if device.os_type == 'slxos':
            po_speed = self._get_current_port_speed(device, intf_type, intf_name)
            actual_line_speed = True
        if po_speed is None:
            if intf_type == "ethernet":
                po_speed = "10000"
            if intf_type == "gigabitethernet":
                po_speed = "1000"
            if intf_type == "tengigabitethernet":
                po_speed = "10000"
            if intf_type == "fortygigabitethernet":
                po_speed = "40000"
            if intf_type == "hundredgigabitethernet":
                po_speed = "100000"

        for intf in intf_name:
            try:
                device.interface.channel_group(name=intf, int_type=intf_type,
                                               port_int=portchannel_num,
                                               channel_type=channel_type, mode=mode_type)

                self.logger.info('Configuring port channel %s with mode as %s'
                                 ' and protocol as active on interface %s is done',
                                 portchannel_num, channel_type, intf)
            except (ValueError, KeyError) as e:
                error_message = str(e.message)
                self.logger.error(error_message)
                self.logger.error('Port Channel %s Creation and setting channel mode %s failed',
                                 portchannel_num,
                                 channel_type)
                sys.exit(-1)

            # no-shut on the interface
            conf_interface = device.interface.admin_state(get=True, int_type=intf_type, name=intf)
            # conf1 = conf_interface.data.find('.//{*}shutdown')
            conf1 = conf_interface
            if not conf1:
                device.interface.admin_state(enabled=True, name=intf, int_type=intf_type)
                self.logger.info('Admin state setting on %s is successfull', intf)

        # Port channel description
        if intf_desc:
            device.interface.description(int_type='port_channel', name=portchannel_num,
                                         desc=intf_desc)

        speed = device.interface.port_channel_speed(name=portchannel_num, get=True)
        if speed is not None:
            if speed == po_speed:
                self.logger.info('Speed %s is already configured under port-channel %s',
                             speed, portchannel_num)
                return False
            else:
                self.logger.info('Shut the port-channel before setting the speed')
                device.interface.admin_state(enabled=False, name=portchannel_num,
                                             int_type='port_channel')

                device.interface.port_channel_speed(name=portchannel_num, delete=True)

                if intf_type != "tengigabitethernet":
                    self.logger.info('Configure port speed %s under port-channel %s',
                                     po_speed, portchannel_num)
                    device.interface.port_channel_speed(name=portchannel_num, po_speed=po_speed)
        elif speed is None and (intf_type == "tengigabitethernet" or intf_type == "ethernet") and\
                not actual_line_speed:
            self.logger.info('port-channel %s is already configured with default speed %s',
                             portchannel_num, po_speed)
        else:
            self.logger.info('Shut the port-channel before setting the speed')
            device.interface.admin_state(enabled=False, name=portchannel_num,
                                         int_type='port_channel')

            self.logger.info('Configure port speed %s under port-channel %s',
                             po_speed, portchannel_num)
            device.interface.port_channel_speed(name=portchannel_num, po_speed=po_speed)

        # no-shut on the port-channel
        conf_port_chan = device.interface.admin_state(get=True,
                                                      int_type='port_channel',
                                                      name=portchannel_num)
        conf_port = conf_port_chan
        if not conf_port:
            device.interface.admin_state(enabled=True, name=portchannel_num,
                                         int_type='port_channel')
            self.logger.info('Admin state setting on port-channel %s is successful',
                             portchannel_num)

        return True

    def _create_port_channel_mlx(self, device, intf_name, intf_type, portchannel_num,
                             channel_type, mode_type, intf_desc):
        """ Configuring the port channel with member ports
        """
        try:
            device.interface.create_port_channel(intf_name, intf_type,
                                           portchannel_num,
                                           mode_type,
                                           intf_desc)
            self.logger.info('Configuring port channel %s with type as %s'
                             ' on interfaces %s is done',
                             portchannel_num, mode_type, intf_name)
        except (ValueError, KeyError) as e:
            error_message = str(e.message)
            self.logger.error(error_message)
            self.logger.error('Port channel creation with id %s desc %s failed',
                             portchannel_num,
                             intf_desc)
            sys.exit(-1)
        return True

    def _disable_isl(self, device, intf_type, intf_name):
        """Disable ISL on the interface.
        """
        if device.os_type != 'nos':
            self.logger.info('Disabling fabric isl is not supported on this platform')
            return False
        try:
            for intf in intf_name:
                conf = device.interface.fabric_isl(get=True, name=intf, int_type=intf_type)
                if conf is None:
                    return False
                self.logger.info("disabling isl on %s %s", intf_type, intf)
                device.interface.fabric_isl(enabled=False, name=intf, int_type=intf_type)
        except (KeyError, ValueError):
            self.logger.info('Invalid Input values while disabling fabric ISL')
        return True

    def _disable_trunk(self, device, intf_type, intf_name):
        """Disable ISL Fabric Trunk on the interface.
        """
        if device.os_type != 'nos':
            self.logger.info('Disabling fabric trunk is not supported on this platform')
            return False
        try:
            for intf in intf_name:
                conf = device.interface.fabric_trunk(get=True, name=intf, int_type=intf_type)
                if conf is None:
                    return False
                self.logger.info("disabling fabric trunk on  %s %s", intf_type, intf)
                device.interface.fabric_trunk(enabled=False, name=intf, int_type=intf_type)
        except (KeyError, ValueError):
            self.logger.info('Invalid Input values while disabling fabric Trunk')
        return True

    def _fabric_neighbor(self, device, intf_type, intf_name):
        """Fabric neighbor discovery settings on the interface.
        """
        if device.os_type != 'nos':
            self.logger.info('Disabling fabric neighbor is not supported on this platform')
            return False
        try:
            for intf in intf_name:
                conf = device.interface.fabric_neighbor(get=True, name=intf, int_type=intf_type)
                if conf is None:
                    return False
                self.logger.info("fabric neighbor-discovery disable on %s %s", intf_type, intf)
                device.interface.fabric_neighbor(enabled=True, name=intf, int_type=intf_type)
        except (KeyError, ValueError):
            self.logger.info('Invalid Input values while configuring fabric neighbor discovery')

        return True

    def _get_current_port_speed(self, device, intf_type, intf_name):
        """Get the actual line speed on the port.
        """

        exec_cli = CliCMD()
        host_ip = self.host
        host_username = self.auth_snmp[0]
        host_password = self.auth_snmp[1]

        intf = random.choice(intf_name)
        cli_cmd = 'show interface ' + intf_type + " " + intf

        device_type = 'brocade_netiron' if device.os_type == 'NI' else 'brocade_vdx'
        raw_cli_output = exec_cli.execute_cli_command(mgmt_ip=host_ip, username=host_username,
                                                      password=host_password,
                                                      cli_cmd=[cli_cmd], device_type=device_type)
        cli_output = raw_cli_output[cli_cmd]
        tmp_speed = re.search(r'(LineSpeed Actual     : )(\d+)', cli_output)
        port_speed = None
        if tmp_speed is not None:
            port_speed = tmp_speed.group(2)
            if int(tmp_speed.group(2)) not in [1000, 10000, 25000, 40000, 100000]:
                self.logger.error('Invalid actual linespeed found in %s output', cli_cmd)
                raise ValueError('Invalid actual linespeed found in show output')
        return port_speed
