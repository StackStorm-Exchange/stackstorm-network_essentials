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
import sys


class PersistConfigs(NosDeviceAction):
    """
       Implements the logic to save the running or default configs to startup
       on SLXOS Switches .
       Perform 'write memory' operation on MLX switches.
    """

    def run(self, mgmt_ip, username, password, source_name):
        """Run helper methods to implement the desired state.
        """

        changes = []
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
            try:
                self.setup_connection(host=each_host[0], user=each_host[1], passwd=each_host[2])
            except Exception as e:
                self.logger.error(e.message)
                sys.exit(-1)
            changes.append(self.switch_operation(source_name))
        return changes

    @log_exceptions
    def switch_operation(self, source_name):

        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:

            # pylint: disable=no-member
            response_id = device.system.persist_config(src_name=source_name,
                                                       dst_name='startup-config')
            if response_id == 'completed':
                self.logger.info('Persist Configuration on the switch %s is complete', self.host)
                return {'switch_ip': self.host, 'status': response_id}
            elif response_id == 'failed':
                self.logger.error('Persist Configuration on the switch %s failed', self.host)
                return {'switch_ip': self.host, 'status': response_id}
            else:
                self.logger.warning('Persist Configuration on the switch %s is complete.'
                                    'To check the status, use the action '
                                    '`get_persist_configuration_status` '
                                    'by inputting the session_id %s', self.host,
                                    response_id)
                return {'switch_ip': self.host, 'session_id': response_id}
