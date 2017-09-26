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


class ConfigureMacGroup(NosDeviceAction):
    """
       Implements the logic to configure mac group on VDX devices.
       This action achieves the below functionality
           1.Configure mac group.
           2.Configure the mac address list.
    """

    def run(self, mgmt_ip, username, password, mac_group_id, mac_address):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(mac_group_id, mac_address)

        return changes

    @log_exceptions
    def switch_operation(self, mac_group_id, mac_address):

        changes = {}
        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info(
                'successfully connected to %s to Configure Mac Group'
                ' on the device', self.host)

            self._validate_inputs(mac_group_id, mac_address)
            changes['pre_check_group'], macs = self._pre_check_mac_group(device, mac_group_id)
            if changes['pre_check_group']:
                changes['configure_mac_group'] = self._config_mac_group(device, mac_group_id)
            if mac_address is not None:
                changes['configure_entry_macs'] = self._config_entry_macs(device,
                                                                          mac_group_id,
                                                                          entry_macs=mac_address)

            self.logger.info('Closing connection to %s after Configuring Mac Group'
                             'on the device -- all done!',
                             self.host)
        return changes

    def _validate_inputs(self, mac_group_id, mac_address):
        """ Check if inputs are valid or not """

        if mac_address is not None:
            for each_mac in mac_address:
                if not self.is_valid_mac(each_mac):
                    raise ValueError('Invalid MAC Address %s', each_mac)

        if mac_group_id not in range(1, 501):
            raise ValueError('Invalid MAC Group Id %s', mac_group_id)

        return True

    def _pre_check_mac_group(self, device, mac_group_id):
        """ Check if mac group is pre-configured or not """

        out = device.interface.mac_group_create(get=True, mac_group_id=mac_group_id)

        if out is not None and int(out) == mac_group_id:
            self.logger.info('Mac Group %s is pre-existing on the device', mac_group_id)
            return False, out

        return True, out

    def _config_mac_group(self, device, mac_group_id):
        """ Configure mac group """

        try:
            self.logger.info('Configuring Mac Group %s', mac_group_id)
            device.interface.mac_group_create(mac_group_id=mac_group_id)
        except (ValueError, KeyError):
            self.logger.exception("Configuring Mac Group %s Failed", mac_group_id)
            raise ValueError("Configuring Mac Group Failed")

        return True

    def _config_entry_macs(self, device, mac_group_id, entry_macs):
        """ Configure Entry Mac Address for mac group """

        try:
            self.logger.info('Configuring Entry Mac Address %s for Mac Group %s ',
                             entry_macs, mac_group_id)
            for each_mac in entry_macs:
                device.interface.mac_group_mac_create(mac_group_id=mac_group_id,
                                                      mac_address=each_mac)
        except (ValueError, KeyError):
            self.logger.exception('Configuring Entry Mac Address %s for Mac Group %s Failed',
                                  each_mac, mac_group_id)
            raise ValueError("Configuring Mac Group Entry Mac Address Failed")

        return True
