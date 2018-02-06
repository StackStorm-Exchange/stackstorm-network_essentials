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
import itertools


class DeleteBridgeDomain(NosDeviceAction):
    """
       Implements the logic to Delete a BD on SLX devices.
       This action achieves the below functionality
           1.Delete single/list of bridge domains
    """

    def run(self, mgmt_ip, username, password, bridge_domain_id,
            bridge_domain_service_type):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(bridge_domain_id,
                                        bridge_domain_service_type)

        return changes

    @log_exceptions
    def switch_operation(self, bridge_domain_id, bridge_domain_service_type):
        changes = {}
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'successfully connected to %s to Delete bridge domain',
                self.host)

            if device.os_type == 'nos' or device.os_type == 'NI':
                self.logger.error('Operation is not supported on this device')
                raise ValueError('Operation is not supported on this device')

            bridge_domain_list = list(itertools.chain.from_iterable(range(int(ranges[0]),
                                      int(ranges[1]) + 1) for ranges in ((el + [el[0]])[:2]
                                      for el in (miniRange.split('-')
                                      for miniRange in bridge_domain_id.split(',')))))

            changes['bd_delete'] = self._delete_bridge_domain(device,
                                                bridge_domain_service_type,
                                                bridge_domain_list, bridge_domain_id)

            self.logger.info('Closing connection to %s after Deleting '
                             'bridge domain -- all done!',
                             self.host)
        return changes

    def _delete_bridge_domain(self, device, bridge_domain_service_type, bd_list, bd_id):
        """ Deleting the bridge-domain """

        try:
            self.logger.info('Deleting bridge-domain %s', bd_id)
            for each_bd in bd_list:
                device.interface.bridge_domain(bridge_domain=str(each_bd), delete=True,
                                              bridge_domain_service_type=bridge_domain_service_type)
        except (ValueError, KeyError) as e:
            self.logger.exception("Deleting bridge-domain failed due to %s"
                                  % (e.message))
            raise ValueError("Deleting bridge-domain failed")
        return True
