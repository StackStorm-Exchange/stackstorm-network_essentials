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


class ConfigurePolicyMap(NosDeviceAction):
    """
       Implements the logic to configure policy map .
       This action achieves the below functionality
           1.Create the policy map.
           2.Configure policy map class instance.
           3.Configure police values.
    """

    def run(self, mgmt_ip, username, password, policy_map_name, class_name, cir, cbs, eir, ebs):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(policy_map_name, class_name, cir, cbs, eir, ebs)

        return changes

    @log_exceptions
    def switch_operation(self, policy_map_name, class_name, cir, cbs, eir, ebs):
        changes = {}
        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info(
                'successfully connected to %s to configure Policy Map'
                ' on the device', self.host)

            if cir is not None and eir is None and ebs is not None:
                self.logger.exception("Missing mandatory args `eir` to configure `ebs`")
                raise ValueError("`eir` is mandatory args to configure `ebs`")
            elif cir is None:
                if cbs is not None or eir is not None or ebs is not None:
                    self.logger.exception("Missing mandatory args `cir` to configure other values")
                    raise ValueError("`cir` is mandatory args to configure other values")

            changes['check_policy_name'] = self._check_policy_name(device, policy_map_name)
            changes['check_class_name'] = self._check_class_name(device, policy_map_name,
                                                                 class_name)
            if cir is not None:
                changes['check_rates'] = self._pre_check_rates(device, policy_map_name,
                                                               class_name,
                                                               cir, cbs, eir, ebs)
            if changes['check_policy_name']:
                changes['create_policy_name'] = self._config_policy_name(device, policy_map_name)
            if changes['check_class_name']:
                changes['create_class_name'] = self._config_policy_class_name(device,
                                                                              policy_map_name,
                                                                              class_name)
            if cir is not None and changes['check_rates']:
                changes['configure_police'] = self._config_policy_class_police(device,
                                                                               policy_map_name,
                                                                               class_name, cir, cbs,
                                                                               eir, ebs)

            self.logger.info('Closing connection to %s after configuring '
                             'Policy Map on the device -- all done!',
                             self.host)
        return changes

    def _check_policy_name(self, device, policy_map_name):
        """ Check if policy name is pre-configured on the device """

        out = device.interface.policy_map_create(get=True, policy_map_name=policy_map_name)
        if out == policy_map_name:
            self.logger.info("Policy Map Name %s is pre-existing on the device", policy_map_name)
            return False

        return True

    def _check_class_name(self, device, policy_map_name, class_name):
        """ Check if class name is pre-configured on the device """

        out_2 = device.interface.class_map_create(get=True)
        if class_name not in out_2:
            self.logger.exception("Class Map %s is not present on the device", class_name)
            raise ValueError("Class Map is not present on the device", class_name)
        out_1 = device.interface.policy_map_class_map_create(policy_map_name=policy_map_name, class_map_name=class_name, get=True)
        if out_1 == class_name:
            self.logger.info("Policy Map Class Instance %s is pre-existing on Policy Map %s", class_name, policy_map_name)
            return False
        return True

    def _pre_check_rates(self, device, policy_map_name, class_name, cir, cbs, eir, ebs):
        """ Check if rates exists or not """

        out = device.interface.policy_map_class_police(get=True, policy_map_name=policy_map_name,
                                                       class_map_name=class_name)
        if out is not None:
            if out['cir'] is not None and out['cir'] != cir or out['cbs'] is not None and\
                    out['cbs'] != cbs or out['eir'] is not None\
                    and out['eir'] != eir or out['ebs'] is not None and out['ebs'] != ebs:
                self.logger.info("Police Values are pre-existing on Policy Map Class Instance %s",
                                 class_name)
                return False

        return True

    def _config_policy_name(self, device, policy_map_name):
        """ Configure policy map"""

        try:
            self.logger.info('Configuring Policy Map %s', policy_map_name)
            device.interface.policy_map_create(policy_map_name=policy_map_name)
        except (ValueError, KeyError):
            self.logger.exception("Configuring Policy Map %s failed", policy_map_name)
            raise ValueError("Configuring Policy Map failed")

        return True

    def _config_policy_class_name(self, device, policy_map_name, class_name):
        """ Configure policy map class instance"""

        try:
            self.logger.info('Configuring Policy Map Class Instance %s on Policy Map %s',
                             class_name, policy_map_name)
            device.interface.policy_map_class_map_create(policy_map_name=policy_map_name,
                                                         class_map_name=class_name)
        except (ValueError, KeyError):
            self.logger.exception('Configuring Policy Map Class Instance %s on Policy Map %s'
                                  ' failed', class_name, policy_map_name)
            raise ValueError("Configuring Policy Map Instance Failed")

        return True

    def _config_policy_class_police(self, device, policy_map_name, class_name, cir, cbs, eir, ebs):
        """ Configure police values"""

        try:
            self.logger.info('Configuring Class Police Values on Policy Map Class Instance %s',
                             class_name)
            device.interface.policy_map_class_police(policy_map_name=policy_map_name,
                                                     class_map_name=class_name, cir=cir, cbs=cbs,
                                                     ebs=ebs, eir=eir)
        except (ValueError, KeyError):
            self.logger.exception('Configuring Class Police Values on Policy Map Class Instance %s'
                                  ' failed', class_name)
            raise ValueError("Configuring Class Police Values on Policy Map Class Failed")

        return True
