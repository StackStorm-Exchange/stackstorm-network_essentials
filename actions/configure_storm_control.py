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


class ConfigureStormControl(NosDeviceAction):
    """
       Implements the logic to configure storm control on an interface.
       This action achieves the below functionality
           1.Configure Storm Control on an interface.
    """

    def run(self, mgmt_ip, username, password, intf_type, intf_name,
            broadcast_limit_type, broadcast_limit_value, broadcast_limit_action,
            multicast_limit_type, multicast_limit_value, multicast_limit_action,
            unknown_unicast_limit_type, unknown_unicast_limit_value,
            unknown_unicast_limit_action):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(intf_type, intf_name,
                  blt=broadcast_limit_type, blv=broadcast_limit_value,
                  bla=broadcast_limit_action, mlt=multicast_limit_type,
                  mlv=multicast_limit_value, mla=multicast_limit_action,
                  ult=unknown_unicast_limit_type, ulv=unknown_unicast_limit_value,
                  ula=unknown_unicast_limit_action)

        return changes

    @log_exceptions
    def switch_operation(self, intf_type, intf_name, blt, blv, bla, mlv, mlt, mla,
                         ult, ulv, ula):

        changes = {}
        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info(
                'successfully connected to %s to Attach Input/Output Policy Map'
                ' to an interface', self.host)

            changes['check_intf_validity'] = self._check_interface_presence(device,
                                                                          intf_type,
                                                                          intf_name)
            if blt is not None or mlt is not None or ult is not None:
                valid_inputs = self._check_inputs(device, blt, blv, bla, mlt, mlv, mla,
                                                  ult, ulv, ula)

                if valid_inputs:
                    bum_list = self._check_bum_intf(device, intf_type, intf_name,
                                                    blt, blv, bla, mlt, mlv,
                                                    mla, ult, ulv, ula)
                    if bum_list != []:
                        changes['Configure_BUM_Control'] = self._config_bum(device, bum_list,
                                                                            intf_type, intf_name,
                                                                            blt, blv, bla, mlt, mlv,
                                                                            mla, ult, ulv, ula)

            self.logger.info('Closing connection to %s after Attaching Input/Output '
                             'Policy Map to an interface -- all done!',
                             self.host)
        return changes

    def _check_inputs(self, device, blt, blv, bla, mlt, mlv, mla, ult, ulv, ula):
        """ Check if inputs are valid or not """

        if blt is not None:
            if blv is None:
                raise KeyError("Missing args `broadcast_limit_value`")
        if mlt is not None:
            if mlv is None:
                raise KeyError("Missing args `mulitcast_limit_value`")
        if ult is not None:
            if ulv is None:
                raise KeyError("Missing args `unknwon_unicast_limit_value`")

        return True

    def _check_interface_presence(self, device, intf_type, intf_name):
        """ Check if interface is present on the device """

        if intf_type not in device.interface.valid_int_types:
            self.logger.error('Iterface type is not valid. '
                              'Interface type must be one of %s'
                              % device.interface.valid_int_types)
            raise ValueError('Iterface type is not valid. '
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

        return True

    def _check_bum_intf(self, device, intf_type, intf_name, blt, blv, bla, mlt, mlv, mla,
                        ult, ulv, ula):
        """ Check if bum is pre-configured or not """

        out = device.interface.interface_storm_control_ingress_create(get=True,
                                                                      intf_name=intf_name,
                                                                      intf_type=intf_type)
        mylist = ['broadcast', 'unknown-unicast', 'multicast']
        if out is not None:
            if blt is not None and 'broadcast' in out:
                self.logger.info("BUM storm control is already active for the "
                                 "broadcast traffic")
                mylist.remove('broadcast')
            elif blt is None and 'broadcast' in out:
                mylist.remove('broadcast')

            if mlt is not None and 'multicast' in out:
                self.logger.info("BUM storm control is already active for the "
                                 "multiast traffic")
                mylist.remove('multicast')
            elif mlt is None and 'multicast' in out:
                mylist.remove('multicast')

            if ult is not None and 'unknown-unicast' in out:
                self.logger.info("BUM storm control is already active for the "
                                 "unknown-unicast traffic")
                mylist.remove('unknown-unicast')
            elif mlt is None and 'unknown-unicast' in out:
                mylist.remove('unknown-unicast')

        return mylist

    def _config_bum(self, device, bum_list, intf_type, intf_name, blt, blv, bla, mlt, mlv,
                    mla, ult, ulv, ula):
        """ Configure BUM Control on the interface"""

        try:
            for each_traff in bum_list:
                self.logger.info('Configuring %s storm control on interface %s %s',
                                 each_traff, intf_type, intf_name)
                if each_traff == 'broadcast':
                    if blt == 'limit-bps':
                        device.interface.interface_storm_control_ingress_create(intf_type=intf_type,
                                                   intf_name=intf_name,
                                                   traffic_type='broadcast',
                                                   rate_format='limit-bps', rate_bps=int(blv),
                                                   bum_action=bla)
                    else:
                        device.interface.interface_storm_control_ingress_create(intf_type=intf_type,
                                                   intf_name=intf_name,
                                                   traffic_type='broadcast',
                                                   rate_format='limit-percent',
                                                   rate_percent=int(blv), bum_action=bla)
                elif each_traff == 'multicast':
                    if mlt == 'limit-bps':
                        device.interface.interface_storm_control_ingress_create(intf_type=intf_type,
                                                   intf_name=intf_name,
                                                   traffic_type='multicast',
                                                   rate_format='limit-bps', rate_bps=int(mlv),
                                                   bum_action=mla)
                    else:
                        device.interface.interface_storm_control_ingress_create(intf_type=intf_type,
                                                   intf_name=intf_name,
                                                   traffic_type='multicast',
                                                   rate_format='limit-percent',
                                                   rate_percent=int(mlv), bum_action=mla)
                else:
                    if ult == 'limit-bps':
                        device.interface.interface_storm_control_ingress_create(intf_type=intf_type,
                                                   intf_name=intf_name,
                                                   traffic_type='unknown-unicast',
                                                   rate_format='limit-bps', rate_bps=int(ulv),
                                                   bum_action=ula)
                    else:
                        device.interface.interface_storm_control_ingress_create(intf_type=intf_type,
                                                   intf_name=intf_name,
                                                   traffic_type='unknown-unicast',
                                                   rate_format='limit-percent',
                                                   rate_percent=int(ulv), bum_action=ula)
        except (ValueError, KeyError):
            self.logger.exception("Configuring Storm Control on Interface Failed")
            raise ValueError("Configuring Storm Control on Interface Failed")

        return True
