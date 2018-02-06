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

import sys

from ne_base import log_exceptions
from ne_base import NosDeviceAction


class DeleteInOutPolicyMap(NosDeviceAction):
    """
       Implements logic to remove policy map on the interface.
    """

    def run(self, mgmt_ip, username, password, intf_type, intf_name, policy_map_name,
            policy_type, rbridge_id):
        """Run helper methods to implement the desired state.
        """

        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as e:
            self.logger.error(e.message)
            sys.exit(-1)
        changes = self.switch_operation(intf_type, intf_name, policy_map_name,
                                        policy_type, rbridge_id)

        return changes

    @log_exceptions
    def switch_operation(self, intf_type, intf_name, policy_map_name, policy_type, rbridge_id):
        changes = {}
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'successfully connected to %s to remove Input/Output Policy Map'
                ' from an interface', self.host)

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
                                                                   intf_type, intf_name, rbridge_id)
            if changes['check_policy_name']:
                changes['check_policy_on_intf'] = self._check_policy_intf(device,
                                                                          policy_map_name,
                                                                          intf_type, intf_name,
                                                                          policy_type)
                if changes['check_policy_on_intf']:
                    changes['create_policy_name'] = self._delete_config_policy(device,
                                                                             policy_map_name,
                                                                             intf_type, intf_name,
                                                                             policy_type)

            self.logger.info('Closing connection to %s after Deleting Input/Output '
                             'Policy Map from the interface -- all done!',
                             self.host)
        return changes

    def _check_policy_name(self, device, policy_map_name, intf_type, intf_name, rbridge_id):
        """ Check if policy name is configured on the device, returns True if it is present """

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
        return True

    def _check_policy_intf(self, device, policy_map_name, intf_type, intf_name, policy_type):
        """ Check if policy name is configured on the interface. """

        out = device.interface.interface_service_policy(get=True, intf_name=intf_name,
                                                        intf_type=intf_type)
        if out is not None:
            if policy_type == 'In':
                if out['in_policy'] is not None and out['in_policy'] == policy_map_name[0]:
                    self.logger.info("In Policy Map %s is matching on the interface %s %s",
                                     policy_map_name[0], intf_type, intf_name)
#                   can be deleted
                    return True
                elif out['in_policy'] is not None and out['in_policy'] != policy_map_name[0]:
                    self.logger.info("Interface %s %s is configured with a different "
                                     "In Policy Map %s", intf_type, intf_name, out['in_policy'])
#                   cannot delete
                    return False
            elif policy_type == 'Out':
                if out['out_policy'] is not None and out['out_policy'] == policy_map_name[0]:
                    self.logger.info("Out Policy Map %s is matching on the interface %s %s",
                                     policy_map_name[0], intf_type, intf_name)
#                   can be deleted
                    return True
                elif out['out_policy'] is not None and out['out_policy'] != policy_map_name[0]:
                    self.logger.info("Interface %s %s is pre-configured with a different "
                                     "Out Policy Map %s", intf_type, intf_name, out['out_policy'])
#                   cannot delete
                    return False
            else:
                if out['out_policy'] is not None and out['out_policy'] == policy_map_name[1] and\
                        out['in_policy'] is not None and out['in_policy'] == policy_map_name[0]:
                    self.logger.info("Both In & Out Policy Maps %s & %s are pre-existing "
                                     "on the interface %s %s",
                                     policy_map_name[0], policy_map_name[1],
                                     intf_type, intf_name)
#                   can be deleted
                    return True
                elif out['out_policy'] is not None and out['out_policy'] != policy_map_name[1] and\
                        out['in_policy'] is not None and out['in_policy'] != policy_map_name[0]:
                    self.logger.info("Interface %s %s is pre-configured with a different "
                                     "In & Out Policy Maps %s & %s ", intf_type, intf_name,
                                     out['in_policy'], out['out_policy'])
#                   cannot delete
                    return False
                elif out['out_policy'] is not None and out['in_policy'] is None or\
                        out['out_policy'] is None and out['in_policy'] is not None:
                    self.logger.info("Interface %s %s is pre-configured with some "
                                     "Policy Maps, Please check", intf_type, intf_name)
#                   cannot delete
                    return False

        return True

    def _delete_config_policy(self, device, policy_map_name, intf_type, intf_name, policy_type):
        """ Remove policy map on the interface"""

        try:
            if policy_type == 'In':
                self.logger.info('Removing Service Input Policy Map %s from Interface %s %s',
                                 policy_map_name[0], intf_type, intf_name)
                device.interface.interface_service_policy(delete=True, in_policy=policy_map_name[0],
                                                          intf_type=intf_type, intf_name=intf_name)
            elif policy_type == 'Out':
                self.logger.info('Removing Service Output Policy Map %s from Interface %s %s',
                                 policy_map_name, intf_type, intf_name)
                device.interface.interface_service_policy(delete=True,
                                                out_policy=policy_map_name[0], intf_type=intf_type,
                                                intf_name=intf_name)
            else:
                self.logger.info('Removing Service Input & Output Policy Map %s, %s '
                                 'from Interface %s %s', policy_map_name[0], policy_map_name[1],
                                 intf_type, intf_name)
                device.interface.interface_service_policy(delete=True, in_policy=policy_map_name[0],
                                                          intf_type=intf_type, intf_name=intf_name)
                device.interface.interface_service_policy(delete=True,
                                                          out_policy=policy_map_name[1],
                                                          intf_type=intf_type, intf_name=intf_name)
        except (ValueError, KeyError):
            self.logger.exception("Removing Service Policy Map %s to Interface failed",
                                  policy_map_name)
            raise ValueError("Removing Policy Map failed from Interface failed")

        return True
