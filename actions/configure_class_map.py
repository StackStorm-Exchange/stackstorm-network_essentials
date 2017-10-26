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
import pyswitch.utilities


class ConfigureClassMap(NosDeviceAction):
    """
       Implements the logic to configure class map .
       This action achieves the below functionality
           1.Configure class map .
           3.Configure match criterion values based on the type.
    """

    def run(self, mgmt_ip, username, password, class_name, match_type, match_value):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(class_name, match_type, match_value)

        return changes

    @log_exceptions
    def switch_operation(self, class_name, match_type, match_value):
        changes = {}
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'successfully connected to %s to configure Class Map'
                ' and Match Criterion', self.host)

            if match_type is not None and match_value is None or\
                    match_type is None and match_value is not None:
                self.logger.exception('Mandatory to pass both `match_type` & `match_value`')
                raise KeyError('Mandatory to pass both `match_type` & `match_value`')

            changes['check_class_name'] = self._check_policy_name(device, class_name,
                                                                  match_type, match_value)
            if match_type is not None:
                changes['check_match'] = self._check_class_name(device, class_name)

            if changes['check_class_name']:
                changes['config_class_name'] = self._config_class_name(device, class_name)

            if match_type is not None and changes['check_match']:
                changes['configure_match'] = self._config_class_match(device,
                                                                      class_name,
                                                                      match_type,
                                                                      match_value)

            self.logger.info('Closing connection to %s after configuring '
                             'Class Map and Match Criterion -- all done!',
                             self.host)
        return changes

    def _check_policy_name(self, device, class_name, match_type, match_value):
        """ Check if policy name is pre-configured on the device """

        if match_type == 'vlan' and not\
                pyswitch.utilities.valid_vlan_id(vlan_id=match_value):
            self.logger.exception('Invalid vlan id passed in `match_value`')
            raise KeyError('Invalid vlan id passed in `match_value`')

        out = device.interface.class_map_create(get=True)
        if class_name in out:
            self.logger.info("Class Name %s is pre-existing on the device", class_name)
            return False

        return True

    def _check_class_name(self, device, class_name):
        """ Check if class name is pre-configured on the device """

        out_2 = device.interface.class_map_get_details(class_map_name=class_name)
        if out_2 is not None:
            if out_2['access_group'] is not None or out_2['vlan'] is not None or\
                    out_2['bridge_domain'] is not None:
                self.logger.info("Class Map %s is pre-existing with a match criterion", class_name)
                return False

        return True

    def _config_class_name(self, device, class_name):
        """ Configure class map"""

        try:
            self.logger.info('Configuring Class Map %s', class_name)
            device.interface.class_map_create(class_map_name=class_name)
        except (ValueError, KeyError):
            self.logger.exception("Configuring Class Map %s failed", class_name)
            raise ValueError("Configuring Class Map failed")

        return True

    def _config_class_match(self, device, class_name, match_type, match_value):
        """ Configure class map match criterion """

        try:
            self.logger.info('Configuring Class Map %s with Match Criterion %s %s',
                             class_name, match_type, match_value)
            if match_type == 'access-group':
                device.interface.class_map_match_access_group(class_map_name=class_name,
                                                            access_group_name=match_value)
            elif match_type == 'bridge-domain':
                device.interface.class_map_match_bridge_domain(class_map_name=class_name,
                                                            bridge_domain_range=match_value)
            else:
                device.interface.class_map_match_vlan(class_map_name=class_name,
                                                      vlan_range=match_value)
        except (ValueError, KeyError):
            self.logger.exception('Configuring Class Map %s match criterion %s'
                                  ' failed', class_name, match_type)
            raise ValueError("Configuring Class Map Match criterion Failed")

        return True
