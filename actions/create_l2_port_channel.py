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
           protocol, mode, intf_desc):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}
        if protocol == "modeon":
            protocol = "on"

        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s to create port channel', self.host)
            if device.os_type == 'slxos':
                if mode != "standard":
                    self.logger.info('SLXOS only supports port-channel type as standard')
                    sys.exit(-1)
            changes['pre_validation'] = self._check_requirements(device, ports, intf_type,
                                                                 port_channel_id,
                                                                 intf_desc)
            if changes['pre_validation']:
                changes['port_channel_configs'] = self._create_port_channel(device,
                                                                    intf_name=ports,
                                                                    intf_type=intf_type,
                                                                    portchannel_num=port_channel_id,
                                                                    channel_type=mode,
                                                                    mode_type=protocol,
                                                                    intf_desc=intf_desc)
            self.logger.info('intf_type {0} ports {1}'.format(intf_type, ports))
            changes['fabric_isl_disable'] = self._disable_isl(device, intf_type, ports)
            changes['fabric_trunk_disable'] = self._disable_trunk(device, intf_type, ports)
            changes['fabric_neighbor_discovery'] = self._fabric_neighbor(device, intf_type, ports)
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

        result = device.interface.port_channels
        tmp1 = "-" + portchannel_num
        port_chan = "port-channel" + tmp1

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
            except (ValueError, KeyError):
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
        elif speed is None and (intf_type == "tengigabitethernet" or intf_type == "ethernet"):
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

    def _disable_isl(self, device, intf_type, intf_name):
        """Disable ISL on the interface.
        """
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
