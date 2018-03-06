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
           protocol, mode, port_channel_desc, port_speed):
        """Run helper methods to implement the desired state.
        """
        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as e:
            self.logger.error(e.message)
            sys.exit(-1)
        changes = {}
        if protocol == "modeon":
            protocol = "on"

        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info('successfully connected to %s to create port channel', self.host)

            if device.os_type not in ['slxos', 'nos'] and port_speed is not None:
                self.logger.error('port_speed args is not valid on this platform ')
                sys.exit(-1)
            if device.os_type == 'slxos':
                if mode != "standard":
                    self.logger.error('SLXOS only supports port-channel type as standard')
                    sys.exit(-1)
            if device.os_type == 'NI':
                if mode != "standard":
                    self.logger.error('NI only supports port-channel type as standard')
                    sys.exit(-1)
                if protocol == "on":
                    protocol = "static"
                elif protocol == "active":
                    protocol = "dynamic"
                else:
                    self.logger.error('NI doesnt support port-channel protocol %s', protocol)
                    sys.exit(-1)

            changes['pre_validation'], po_exists = self._check_requirements(device, ports,
                                                                 intf_type,
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
                                                              intf_desc=port_channel_desc,
                                                              po_exists=po_exists)
                else:
                    changes['port_channel_configs'] = self._create_port_channel(device,
                                                              intf_name=ports,
                                                              intf_type=intf_type,
                                                              portchannel_num=port_channel_id,
                                                              channel_type=mode,
                                                              mode_type=protocol,
                                                              intf_desc=port_channel_desc,
                                                              port_speed=port_speed)
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
        po_exists = False
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
                self.logger.error('Port-channel name/description cannot be NULL for NI')
                sys.exit(-1)

        result = device.interface.port_channels
        tmp1 = "-" + portchannel_num
        port_chan = "port-channel" + tmp1
        # For NI/MLX Portchannel name/descr is mandatory
        if device.os_type == 'NI':
            port_chan = intf_desc

        # Verify if the port channel to interface mapping is already existing
        for port_chann in result:
            if port_chann['interface-name'] == port_chan and \
               port_chann['aggregator_id'] == portchannel_num:
                if port_chann['aggregator_type'] == 'standard':
                    po_exists = True
                    for interfaces in port_chann['interfaces']:
                        if interfaces['interface-name'] in intf_name:
                            self.logger.info(
                                'Port Channel %s to interface %s mapping is'
                                ' pre-existing',
                                port_chann['aggregator_id'], interfaces['interface-name'])
                            return False, po_exists
            else:
                for interfaces in port_chann['interfaces']:
                    if interfaces['interface-name'] in intf_name:
                        self.logger.error('Interface %s is already mapped to a'
                                ' different port channel id: %s desc: %s',
                                interfaces['interface-name'], port_chann['aggregator_id'],
                                port_chann['interface-name'])
                        sys.exit(-1)
        return True, po_exists

    def _create_port_channel(self, device, intf_name, intf_type, portchannel_num,
                             channel_type, mode_type, intf_desc, port_speed):
        """ Configuring the port channel and channel-group,
            Admin state up on interface and port-channel."""
        actual_line_speed = False
        po_speed = None
        if device.os_type in ['slxos', 'nos']:
            if port_speed is None:
                po_speed = self._get_current_port_speed(device, intf_type, intf_name)
            else:
                po_speed = port_speed
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
                self.logger.error('Port Channel %s Creation and setting channel mode %s failed'
                                  ' due to %s ', portchannel_num, channel_type, str(e.message))
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
                             channel_type, mode_type, intf_desc, po_exists):
        """ Configuring the port channel with member ports
        """
        try:
            device.interface.create_port_channel(intf_name, intf_type,
                                           portchannel_num,
                                           mode_type,
                                           po_exists,
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
        port_speed = None
        try:
            intf_list = device.interface.get_media_details_requesst
        except:
            self.logger.error('Unable to fetch the actual line speed of the interfaces')
            raise ValueError('Unable to fetch the actual line speed of the interfaces')

        if intf_list is None:
            return port_speed

        speed_list = []
        for each_int in intf_list:
            if each_int['interface-name'] in intf_name:
                speed_list.append(each_int['sfp_speed'])
        if speed_list != [] and len(speed_list) != len(intf_name):
            self.logger.error('Port channel group member ports %s cannot be of different port'
                              ' speeds', intf_name)
            raise ValueError('Port channel group member ports cannot '
                             'be of different port speeds')
        if speed_list != []:
            if list(set(speed_list))[0] == "1Gbps":
                port_speed = "1000"
            if list(set(speed_list))[0] == "10Gbps":
                port_speed = "10000"
            if list(set(speed_list))[0] == "25Gbps":
                port_speed = "25000"
            if list(set(speed_list))[0] == "40Gbps":
                port_speed = "40000"
            if list(set(speed_list))[0] == "100Gbps":
                port_speed = "100000"

        return port_speed
