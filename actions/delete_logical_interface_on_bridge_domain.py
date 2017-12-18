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


class DeleteLogicalInterfaceOnBridgeDomain(NosDeviceAction):
    """
       Implements the logic to Delete a LIG under a BD on SLX devices.
       This action achieves the below functionality
           1.Delete single/list of LIFs under a bridge domains
    """

    def run(self, mgmt_ip, username, password, bridge_domain_id,
            bridge_domain_service_type, intf_type, logical_interface_number):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(bridge_domain_id,
                                        bridge_domain_service_type, intf_type,
                                        logical_interface_number)

        return changes

    @log_exceptions
    def switch_operation(self, bridge_domain_id, bridge_domain_service_type,
                         intf_type, logical_interface_number):
        changes = {}
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'successfully connected to %s to Delete logical interfaces on'
                ' bridge domain', self.host)

            changes['pre_check_bd'] = self._check_bd_presence(device,
                                                              bridge_domain_id, intf_type,
                                                              bridge_domain_service_type)
            if logical_interface_number is not None and changes['pre_check_bd']:
                lif_name = logical_interface_number.split(',')
                changes['bd_lif_delete'] = self._delete_lif(device,
                                                            bridge_domain_service_type,
                                                            bridge_domain_id,
                                                            lif_name,
                                                            intf_type)
            else:
                changes['bd_lif_delete'] = self._delete_lif_all(device, bridge_domain_service_type,
                                                               bridge_domain_id,
                                                               intf_type)

            self.logger.info('Closing connection to %s after Deleting logical interfaces on '
                             'bridge domain -- all done!',
                             self.host)
        return changes

    def _check_bd_presence(self, device, bridge_domain_id, intf_type,
                           bridge_domain_service_type):

        if intf_type is not None and intf_type != 'both' and\
                intf_type not in device.interface.valid_int_types:
            self.logger.error('Interface type %s is not valid. '
                              'Interface type must be one of %s',
                              device.interface.valid_int_types)
            raise ValueError('Interface type is not valid. '
                             'Interface type must be one of %s'
                             % device.interface.valid_int_types)

        bd_check = device.interface.bridge_domain(bridge_domain=bridge_domain_id,
                                     bridge_domain_service_type=bridge_domain_service_type,
                                     get=True)
        if bd_check is None:
            self.logger.info('bridge_domain_id %s with service-type %s is not present '
                             'on the device', bridge_domain_id, bridge_domain_service_type)
            return False

        return True

    def _delete_lif(self, device, bridge_domain_service_type, bridge_domain_id, lif_list,
                    intf_type):
        """ Deleting the lif_name under the bridge_domain"""

        try:
            for each_lif in lif_list:
                self.logger.info('Deleting lif_name %s %s under bridge-domain %s', intf_type,
                                 each_lif,
                                 bridge_domain_id)
                device.interface.bridge_domain_logical_interface(delete=True, intf_type=intf_type,
                                              bridge_domain=bridge_domain_id, lif_name=each_lif,
                                              bridge_domain_service_type=bridge_domain_service_type)
        except ValueError as e:
            self.logger.exception("Deleting lif_name under the bridge-domain failed %s"
                                  % (e.message))
            raise ValueError("Deleting lif_name under the bridge-domain failed")
        return True

    def _delete_lif_all(self, device, bridge_domain_service_type, bridge_domain_id, intf_type):
        """ Deleting all the lif_name under the bridge_domain"""

        try:
            if intf_type == 'both':
                self.logger.info('Deleting all LIFs under the bridge_domain_id %s',
                                 bridge_domain_id)
                for each in ['ethernet', 'port_channel']:
                    device.interface.bridge_domain_logical_interface(delete=True, intf_type=each,
                                            bridge_domain=bridge_domain_id,
                                            bridge_domain_service_type=bridge_domain_service_type)
            else:
                self.logger.info('Deleting all %s LIFs under the bridge_domain_id %s', intf_type,
                                 bridge_domain_id)
                device.interface.bridge_domain_logical_interface(delete=True, intf_type=intf_type,
                                            bridge_domain=bridge_domain_id,
                                            bridge_domain_service_type=bridge_domain_service_type)
        except ValueError as e:
            self.logger.exception("Deleting all lifs under the bridge-domain failed %s"
                                  % (e.message))
            raise ValueError("Deleting all lifs under the bridge-domain failed")
        return True
