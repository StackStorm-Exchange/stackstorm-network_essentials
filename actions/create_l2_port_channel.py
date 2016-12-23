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


class CreatePortChannel(NosDeviceAction):
    """
       Implements the logic to create port-channel on an interface on VDX and SLX devices .
       This action achieves the below functionality
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
        try:
            device = self.asset(ip_addr=self.host, auth=self.auth)
            self.logger.info('successfully connected to %s to create port channel',
                             self.host)
        except AttributeError as e:
            raise ValueError('Failed to connect to %s due to %s', self.host, e.message)
        except ValueError as verr:
            self.logger.error("Error while logging in to %s due to %s",
                              self.host, verr.message)
            raise ValueError("Error while logging in to %s due to %s",
                             self.host, verr.message)
        except self.ConnectionError as cerr:
            self.logger.error("Connection failed while logging in to %s due to %s",
                              self.host, cerr.message)
            raise ValueError("Connection failed while logging in to %s due to %s",
                             self.host, cerr.message)
        except self.RestInterfaceError as rierr:
            self.logger.error("Failed to get a REST response while logging in "
                              "to %s due to %s", self.host, rierr.message)
            raise ValueError("Failed to get a REST response while logging in "
                             "to %s due to %s", self.host, rierr.message)

        changes['pre_validation'] = self._check_requirements(device, ports, intf_type,
                                                             port_channel_id,
                                                             intf_desc)
        if changes['pre_validation']:
            changes['port_channel_configs'] = \
                self._create_port_channel(device, intf_name=ports, intf_type=intf_type,
                                          portchannel_num=port_channel_id,
                                          channel_type=mode, mode_type=protocol,
                                          intf_desc=intf_desc)
            changes['fabric_isl_disable'] = self._disable_isl(device, intf_type, ports)
            changes['fabric_trunk_disable'] = self._disable_trunk(device, intf_type, ports)
            changes['fabric_neighbor_discovery'] = self._fabric_neighbor(device, intf_type, ports)
        self.logger.info('closing connection to %s after'
                         ' configuring port channel -- all done!', self.host)
        return changes

    def _check_requirements(self, device, intf_name, intf_type, portchannel_num, intf_desc):
        """ Verify if the port channel already exists """

        for each in intf_name:
            r1 = self.validate_interface(intf_type=intf_type, intf_name=each)
            if not r1:
                self.logger.error('Not a valid interface type %s or number %s', intf_type, each)
                raise ValueError('Not a valid interface type or number', intf_type, each)

        r2 = self.validate_interface(intf_type='port_channel', intf_name=portchannel_num)
        if not r2:
            self.logger.error('Port Channel number %s is not a valid value', portchannel_num)
            raise ValueError('Port Channel number %s is not a valid value', portchannel_num)

        valid_desc = True
        if intf_desc:
            valid_desc = self.check_int_description(intf_description=intf_desc)
            if not valid_desc:
                self.logger.error('Invalid interface description %s', intf_desc)
                raise ValueError('Invalid interface description %s', intf_desc)
            members = self._get_port_channel_members(device, portchannel_num)
        port_channels = self._get_port_channels(device)

        # Verify if the port channel to interface mapping is already existing
        if port_channels:
            for port_chann in port_channels:
                members = self._get_port_channel_members(device=device,
                                                         portchannel_num=int(port_chann
                                                                             ['aggregator-id']))
                if members:
                    for member in members:
                        if member['interface-type'] == intf_type \
                                and member['interface-name'] in intf_name:
                            if portchannel_num == int(port_chann['aggregator-id']):
                                self.logger.info(
                                    'Port Channel %s to interface %s %s mapping is'
                                    ' pre-existing',
                                    portchannel_num, member['interface-type'],
                                    member['interface-name'])
                            else:
                                self.logger.info('Interface %s %s is already mapped to a'
                                                 ' different port channel %s',
                                                 member['interface-type'],
                                                 member['interface-name'],
                                                 port_chann['aggregator-id'])

                            return False
        self.logger.info('Check requirements completed')
        return True

    def _create_port_channel(self, device, intf_name, intf_type, portchannel_num,
                             channel_type, mode_type, intf_desc):
        """ Configuring the port channel and channel-group,
            Admin state up on interface and port-channel."""

        if intf_type == 'ethernet':
            create = device.interface_ethernet_channel_group_update
        elif intf_type == 'gigabitethernet':
            create = device.interface_gigabitethernet_channel_group_update
        elif intf_type == 'tengigabitethernet':
            create = device.interface_tengigabitethernet_channel_group_update
        elif intf_type == 'fortygigabitethernet':
            create = device.interface_fortygigabitethernet_channel_group_update
        elif intf_type == 'hundredgigabitethernet':
            create = device.interface_hundredgigabitethernet_channel_group_update
        else:
            self.logger.info('intf_type %s is not supported',
                             intf_type)
            return False

        for intf in intf_name:

            try:
                result = create(intf, port_int=portchannel_num,
                                mode=mode_type, type=channel_type)
                if result[0]:
                    self.logger.info('Configuring port channel %s with mode as %s'
                                     ' and protocol as active on interface %s is done',
                                     portchannel_num, channel_type, intf)
                else:
                    self.logger.info('Port Channel %s Creation and setting channel mode %s failed'
                                     ' due to %s',
                                     portchannel_num,
                                     channel_type,
                                     result[1][0][self.host]['response']['json']['output'])

            except (AttributeError, ValueError) as e:
                self.logger.error('Port Channel %s Creation and setting channel mode %s '
                                 'failed due to %s', portchannel_num, channel_type, e.message)
                raise ValueError(e.message)

            # no-shut on the interface
            intf_admin_state = self._get_interface_admin_state(device, intf_type, intf)
            if 'down' in intf_admin_state:
                intf_update = self._interface_update(device, intf_type, intf, shutdown=False)
                if not intf_update:
                    self.logger.info('Configuring no-shut on interface %s %s failed',
                                     intf_type, intf)
                else:
                    self.logger.info('Successfully configured no-shut on interface')

        # no-shut and description on the port-channel
        port_chan_admin_state = self._get_interface_admin_state(device,
                                                                intf_type='port-channel',
                                                                intf_name=portchannel_num)
        change_shutdown_state = False if port_chan_admin_state == 'down' else None

        conf_port_chan = self._interface_update(device,
                                                intf_type='port-channel',
                                                intf_name=portchannel_num,
                                                description=intf_desc,
                                                shutdown=change_shutdown_state)
        if not conf_port_chan:
            self.logger.info('Configuring no-shut and description on '
                             'port_channel %s failed',
                             portchannel_num)
            return False
        else:
            self.logger.info('Successfully configured no-shut and description')
        return True

    def _disable_isl(self, device, intf_type, intf_name):
        """Disable ISL on the interface.
        """
        self.logger.info('disabling fabric ISL settings on the interface ')
        if intf_type == 'ethernet':
            update = device.interface_ethernet_fabric_isl_update
        elif intf_type == 'gigabitethernet':
            update = device.interface_gigabitethernet_fabric_isl_update
        elif intf_type == 'tengigabitethernet':
            update = device.interface_tengigabitethernet_fabric_isl_update
        elif intf_type == 'fortygigabitethernet':
            update = device.interface_fortygigabitethernet_fabric_isl_update
        elif intf_type == 'hundredgigabitethernet':
            update = device.interface_hundredgigabitethernet_fabric_isl_update
        else:
            self.logger.info('intf_type %s is not supported',
                             intf_type)
            return False

        try:
            for intf in intf_name:
                self.logger.info("disabling fabric ISL "
                                 "settings on %s %s", intf_type, intf)
                conf_intf = update(intf, fabric_isl_enable=False)
                if conf_intf[0] == 'True':
                    self.logger.info('disabling fabric trunk on %s %s is done', intf_type, intf)

                elif conf_intf[0] == 'False':
                    self.logger.error('disabling fabric trunk on %s %s failed due to %s',
                                     intf_type,
                                     intf,
                                     conf_intf[1][0][self.host]
                                     ['response']['json']['output'])
        except (KeyError, ValueError, AttributeError):
            self.logger.error('Invalid Input values while disabling fabric trunk')
            return False
        return True

    def _disable_trunk(self, device, intf_type, intf_name):
        """Disable fabric trunk on the interface."""
        self.logger.info('disabling fabric trunk on the interface ')
        if intf_type == 'ethernet':
            update = device.interface_ethernet_fabric_trunk_update
        elif intf_type == 'gigabitethernet':
            update = device.interface_gigabitethernet_fabric_trunk_update
        elif intf_type == 'tengigabitethernet':
            update = device.interface_tengigabitethernet_fabric_trunk_update
        elif intf_type == 'fortygigabitethernet':
            update = device.interface_fortygigabitethernet_fabric_trunk_update
        elif intf_type == 'hundredgigabitethernet':
            update = device.interface_hundredgigabitethernet_fabric_trunk_update
        else:
            self.logger.info('intf_type %s is not supported',
                             intf_type)
            return False

        try:
            for intf in intf_name:
                self.logger.info("disabling fabric trunk on %s %s", intf_type, intf)
                conf_intf = update(intf, fabric_trunk_enable=True)
                if conf_intf[0] == 'True':
                    self.logger.info('disabling fabric trunk on %s %s is done', intf_type, intf)

                elif conf_intf[0] == 'False':
                    self.logger.error('disabling fabric trunk on %s %s failed due to %s',
                                     intf_type,
                                     intf,
                                     conf_intf[1][0][self.host]
                                     ['response']['json']['output'])
        except (KeyError, ValueError, AttributeError):
            self.logger.info('Invalid Input values while disabling fabric trunk')
            return False
        return True

    def _fabric_neighbor(self, device, intf_type, intf_name):
        """Fabric neighbor discovery settings on the interface.
        """
        self.logger.info('disabling fabric neighbor discovery settings on the interface ')
        if intf_type == 'ethernet':
            update = device.interface_ethernet_fabric_neighbor_discovery_update
        elif intf_type == 'gigabitethernet':
            update = device.interface_gigabitethernet_fabric_neighbor_discovery_update
        elif intf_type == 'tengigabitethernet':
            update = device.interface_tengigabitethernet_fabric_neighbor_discovery_update
        elif intf_type == 'fortygigabitethernet':
            update = device.interface_fortygigabitethernet_fabric_neighbor_discovery_update
        elif intf_type == 'hundredgigabitethernet':
            update = device.interface_hundredgigabitethernet_fabric_neighbor_discovery_update
        else:
            self.logger.info('intf_type %s is not supported',
                             intf_type)
            return False

        try:
            for intf in intf_name:
                self.logger.info("disabling fabric neighbor discovery "
                                 "settings on %s %s", intf_type, intf)
                conf_intf = update(intf, disable=True)
                if conf_intf[0] == 'True':
                    self.logger.info('disabling fabric trunk on %s %s is done', intf_type, intf)

                elif conf_intf[0] == 'False':
                    self.logger.error('disabling fabric trunk on %s %s failed due to %s',
                                     intf_type,
                                     intf,
                                     conf_intf[1][0][self.host]
                                     ['response']['json']['output'])
        except (KeyError, ValueError, AttributeError):
            self.logger.info('Invalid Input values while disabling fabric trunk')
            return False
        return True
