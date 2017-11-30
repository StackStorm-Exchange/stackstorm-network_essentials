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


class ConfigureInOutPolicyMap(NosDeviceAction):
    """
       Implements the logic to configure policy map .
       This action achieves the below functionality
           1.Create the policy map.
           2.Configure policy map class instance.
           3.Configure police values.
    """

    def run(self, mgmt_ip, username, password, intf_type, intf_name, policy_map_name,
            policy_type, rbridge_id):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(intf_type, intf_name, policy_map_name, policy_type,rbridge_id)

        return changes

    @log_exceptions
    def switch_operation(self, intf_type, intf_name, policy_map_name, policy_type,rbridge_id):
        changes = {}
        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info(
                'successfully connected to %s to Attach Input/Output Policy Map'
                ' to an interface', self.host)

            if policy_type == 'Both' and len(policy_map_name) < 2:
                self.logger.exception('Both In & Out Policy Map names are Mandatory'
                                      ' if policy_type is `Both`')
                raise ValueError('Both In & Out Policy Map names are Mandatory'
                                 ' if policy_type is `Both`')
            if policy_type != 'Both' and len(policy_map_name) > 1:
                self.logger.exception('To Configure In or Out Policy Map '
                                      '`policy_map_name` args must be a single value')
                raise ValueError('To Configure In or Out Policy Map '
                                 '`policy_map_name` args must be a single value')

            changes['check_policy_name'] = self._check_policy_name(device, policy_map_name,
                                                                   intf_type, intf_name,rbridge_id)
            if changes['check_policy_name']:
                changes['check_policy_on_intf'] = self._check_policy_intf(device,
                                                                          policy_map_name,
                                                                          intf_type, intf_name,
                                                                          policy_type)
                if changes['check_policy_on_intf']:
                    changes['create_policy_name'] = self._config_policy_name(device,
                                                                             policy_map_name,
                                                                             intf_type, intf_name,
                                                                             policy_type)

            self.logger.info('Closing connection to %s after Attaching Input/Output '
                             'Policy Map to an interface -- all done!',
                             self.host)
        return changes

    def _check_policy_name(self, device, policy_map_name, intf_type, intf_name,rbridge_id):
        """ Check if policy name is pre-configured on the device """

        os = device.os_type

        if intf_type not in device.interface.valid_int_types:
            self.logger.error('Iterface type is not valid. '
                              'Interface type must be one of %s'
                              % device.interface.valid_int_types)
            raise ValueError('Iterface type is not valid. '
                             'Interface type must be one of %s'
                             % device.interface.valid_int_types)
        if os == 'nos':
            if not self.validate_interface(intf_type, intf_name, rbridge_id):
                  msg = "Input is not a valid Interface"
                  self.logger.error(msg)
                  raise ValueError(msg)
#        if os != 'nos':
#            if not self.validate_interface(intf_type, intf_name, os):
#                raise ValueError('Interface %s is not valid' % (intf_name))

        if not device.interface.interface_exists(int_type=intf_type,
                                                 name=intf_name):
             self.logger.error('Interface %s %s is not present on the Device'
                              % (intf_type, intf_name))
             raise ValueError('Interface %s %s is not present on the Device'
                            % (intf_type, intf_name))

        for each_map in policy_map_name:
            out = device.interface.policy_map_create(get=True, policy_map_name=each_map)
            if out is None:
                self.logger.info("%s Policy Map Name %s is not present on the device", out,each_map)
                return True 

        return True

    def _check_policy_intf(self, device, policy_map_name, intf_type, intf_name, policy_type):
        """ Check if policy name on interface is pre-configured or not """

        out = device.interface.interface_service_policy(get=True, intf_name=intf_name,
                                                        intf_type=intf_type)
        if out is not None:
            if policy_type == 'In':
                if out['in_policy'] is not None and out['in_policy'] == policy_map_name[0]:
                    self.logger.info("In Policy Map %s is pre-existing on the interface %s %s",
                                     policy_map_name[0], intf_type, intf_name)
                    return False
                elif out['in_policy'] is not None and out['in_policy'] != policy_map_name[0]:
                    self.logger.info("Interface %s %s is pre-configured with a different "
                                     "In Policy Map %s", intf_type, intf_name, out['in_policy'])
                    return False
            elif policy_type == 'Out':
                if out['out_policy'] is not None and out['out_policy'] == policy_map_name[0]:
                    self.logger.info("Out Policy Map %s is pre-existing on the interface %s %s",
                                     policy_map_name[0], intf_type, intf_name)
                    return False
                elif out['out_policy'] is not None and out['out_policy'] != policy_map_name[0]:
                    self.logger.info("Interface %s %s is pre-configured with a different "
                                     "Out Policy Map %s", intf_type, intf_name, out['out_policy'])
                    return False
            else:
                if out['out_policy'] is not None and out['out_policy'] == policy_map_name[1] and\
                        out['in_policy'] is not None and out['in_policy'] == policy_map_name[0]:
                    self.logger.info("Both In & Out Policy Maps %s & %s are pre-existing "
                                     "on the interface %s %s",
                                     policy_map_name[0], policy_map_name[1],
                                     intf_type, intf_name)
                    return False
                elif out['out_policy'] is not None and out['out_policy'] != policy_map_name[1] and\
                        out['in_policy'] is not None and out['in_policy'] != policy_map_name[0]:
                    self.logger.info("Interface %s %s is pre-configured with a different "
                                     "In & Out Policy Maps %s & %s ", intf_type, intf_name,
                                     out['in_policy'], out['out_policy'])
                    return False
                elif out['out_policy'] is not None and out['in_policy'] is None or\
                        out['out_policy'] is None and out['in_policy'] is not None:
                    self.logger.info("Interface %s %s is pre-configured with some "
                                     "Policy Maps, Please check", intf_type, intf_name)
                    return False

        return True

    def _config_policy_name(self, device, policy_map_name, intf_type, intf_name, policy_type):
        """ Configure policy map on the interface"""

        try:
            if policy_type == 'In':
                self.logger.info('Atttaching Service Input Policy Map %s to Interface %s %s',
                                 policy_map_name[0], intf_type, intf_name)
                device.interface.interface_service_policy(in_policy=policy_map_name[0],
                                                          intf_type=intf_type, intf_name=intf_name)
            elif policy_type == 'Out':
                self.logger.info('Attaching Service Output Policy Map %s to Interface %s %s',
                                 policy_map_name, intf_type, intf_name)
                device.interface.interface_service_policy(out_policy=policy_map_name[0],
                                                          intf_type=intf_type, intf_name=intf_name)
            else:
                self.logger.info('Attaching Service Input & Output Policy Map %s, %s '
                                 'to Interface %s %s', policy_map_name[0], policy_map_name[1],
                                 intf_type, intf_name)
                device.interface.interface_service_policy(in_policy=policy_map_name[0],
                                                          intf_type=intf_type, intf_name=intf_name)
                device.interface.interface_service_policy(out_policy=policy_map_name[1],
                                                          intf_type=intf_type, intf_name=intf_name)
        except (ValueError, KeyError):
            self.logger.exception("Attaching Service Policy Map %s to Interface failed",
                                  policy_map_name)
            raise ValueError("Attaching Policy Map failed to Interface failed")

        return True
