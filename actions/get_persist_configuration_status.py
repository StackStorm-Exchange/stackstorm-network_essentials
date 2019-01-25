# Copyright 2016 Brocade Communications Systems, Inc.

# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import time
from ne_base import NosDeviceAction
from ne_base import log_exceptions


class GetPersistConfig(NosDeviceAction):
    """ Action that retrieves data from the inventory service.
    """

    def run(self, mgmt_ip, username, password, session_id):

        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as e:
            self.logger.error(e.message)
            sys.exit(-1)
        changes = self.switch_operation(session_id)

        return changes

    @log_exceptions
    def switch_operation(self, session_id):

        # pylint: disable=no-member
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:

            retry_code = 0
            while retry_code < 2:
                retry_code = retry_code + 1
                save_status = device.system.persist_config_status(session_id=session_id)
                if save_status != 'completed':
                    self.logger.warning('Persist configuration operation is still in-progess,'
                                        ' Retrying to check the completion status')
                    time.sleep(15)
                else:
                    self.logger.info('Persist configuration operation completed on %s', self.host)
                    return {'switch_ip': self.host, 'session_id': session_id}
            else:
                self.logger.warning('Persist configuration operation is still in progess and '
                                    'is taking longer time than expected. '
                                    'Retry after some time')
                return {'switch_ip': self.host, 'session_id': session_id}
