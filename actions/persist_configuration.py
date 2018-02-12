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


class PersistConfigs(NosDeviceAction):
    """
       Implements the logic to save the running or default configs to startup
       on SLXOS Switches .
    """

    def run(self, mgmt_ip, username, password, source_name):
        """Run helper methods to implement the desired state.
        """

        if username is None:
            username = []
            for index in range(len(mgmt_ip)):
                username.append(None)
        else:
            if len(username) != len(password) or len(mgmt_ip) != len(username) or\
                    len(mgmt_ip) != len(password):
                raise ValueError('`mgmt_ip`, `username` and `password` must of same length')

        if password is None:
            password = []
            for index in range(len(mgmt_ip)):
                password.append(None)

        for each_host in zip(mgmt_ip, username, password):
            self.setup_connection(host=each_host[0], user=each_host[1], passwd=each_host[2])
            self.switch_operation(source_name)

    @log_exceptions
    def switch_operation(self, source_name):
        changes = {}
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'Successfully connected to %s to perform persist configuration operation',
                self.host)

            changes['persist_config'] = self._persist_config(device, source_name)

            self.logger.info('Closing connection to %s after'
                             ' performing persist configuration operation  -- all done!',
                             self.host)
        return changes

    def _persist_config(self, device, source_name):

        try:
            device.system.persist_config(src_name=source_name, dst_name='startup-config')
        except (ValueError, KeyError) as e:
            self.logger.error('Persist configuration operation failed due to %s',
                e.message)
            raise ValueError('Persist configuration operation failed')
        return True
