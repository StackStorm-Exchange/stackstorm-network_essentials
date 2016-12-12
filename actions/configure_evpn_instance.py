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


class ConfigureEvpnInstance(NosDeviceAction):
    """
       Implements the logic to configure EVPN instance on VDX switches
       This action acheives the below functionality
           Configures EVPN instance with options specified
    """

    def run(self, mgmt_ip, username, password, evi_name, rbridge_id,
            duplicate_mac_timer, max_count, ignore_as):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}
        with self.mgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s', self.host)
            if type(rbridge_id) is list:
                rbridge_id = rbridge_id[0]

            if rbridge_id is None:
                rb_list = self._vlag_pair(device)
            else:
                rb_list = rbridge_id
            changes['evpn-instance'] = self._configure_evpn_instance(device,
                                                                     rb_list,
                                                                     evi_name,
                                                                     str(duplicate_mac_timer),
                                                                     str(max_count),
                                                                     ignore_as)
            self.logger.info('closing connection to %s after configuring EVPN instance'
                             '-- all done!', self.host)
        return changes

    def _configure_evpn_instance(self, device, rb_list, evi_name, duplicate_mac_timer, max_count,
                                 ignore_as):
        """Configuring EVPN instance under config mode.
        """
        is_evpn_instance_exist = False
        for rb in rb_list:
            get_code = device.interface.create_evpn_instance(get=True,
                                                             rbridge_id=rb)
            new_code = get_code.data.find('.//{*}instance-name')
            if new_code is not None:
                new_get_code = get_code.data.find('.//{*}instance-name').text
            else:
                new_get_code = None
            if (new_get_code is not None) and (new_get_code != evi_name):
                self.logger.info('EVPN instance already configured on rbridge %s ', rb)
                is_evpn_instance_exist = True
            elif new_get_code == evi_name:
                self.logger.info('EVPN instance already configured on rbridge %s ', rb)
                get_code1 = device.interface.create_evpn_instance(get=True,
                                                                  rbridge_id=rb,
                                                                  evpn_instance_name=evi_name)
                if get_code1.data.find('.//{*}duplicate-mac-timer-value') is not None:
                    self.logger.info('EVPN instance already configured with timer-value on %s', rb)
                else:
                    device.interface.evpn_instance_duplicate_mac_timer(rbridge_id=rb,
                                                                  evpn_instance_name=evi_name,
                                                      duplicate_mac_timer_value=duplicate_mac_timer)
                if get_code1.data.find('.//{*}max-count') is not None:
                    self.logger.info('EVPN instance already configured with Mac-count on %s', rb)
                else:
                    device.interface.evpn_instance_mac_timer_max_count(rbridge_id=rb,
                                                                   evpn_instance_name=evi_name,
                                                                   max_count=max_count)
                if get_code1.data.find('.//{*}ignore-as') is not None:
                    self.logger.info('EVPN instance already configured with Ignore-as on %s', rb)
                    is_evpn_instance_exist = True
                else:
                    device.interface.evpn_instance_rt_both_ignore_as(rbridge_id=rb,
                                                                     evpn_instance_name=evi_name)
                if get_code1.data.find('.//{*}route-distinguisher') is not None:
                    self.logger.info('EVPN instance already configured with the Rd auto on %s', rb)
                    is_evpn_instance_exist = True
                else:
                    device.interface.evpn_instance_rd_auto(rbridge_id=rb, instance_name=evi_name)
            else:
                try:
                    self.logger.info('Configuring EVPN instance on rbridge %s ', rb)
                    device.interface.create_evpn_instance(rbridge_id=rb,
                                                          evpn_instance_name=evi_name)
                    self.logger.info('Successfuly created EVPN instance')
                    device.interface.evpn_instance_rt_both_ignore_as(rbridge_id=rb,
                                                                     evpn_instance_name=evi_name)
                    self.logger.info('Completed configuring rd auto')
                    device.interface.evpn_instance_rd_auto(rbridge_id=rb, instance_name=evi_name)
                    self.logger.info('Completed configuring duplicate mac timer')
                    device.interface.evpn_instance_duplicate_mac_timer(rbridge_id=rb,
                                                                   evpn_instance_name=evi_name,
                                                      duplicate_mac_timer_value=duplicate_mac_timer)
                    self.logger.info('Completed configuring duplicate mac timer')

                    device.interface.evpn_instance_mac_timer_max_count(rbridge_id=rb,
                                                                   evpn_instance_name=evi_name,
                                                                   max_count=max_count)
                    self.logger.info('Completed configuring max timer max count')
                except ValueError:
                    self.logger.info("Configuring EVPN Instance failed on %s", rb)
                    is_evpn_instance_exist = True
        if is_evpn_instance_exist:
            return False
        return True

    def _vlag_pair(self, device):
        """ Fetch the RB list if VLAG is configured"""

        rb_list = []
        result = device.vcs.vcs_nodes
        for each_rb in result:
            rb_list.append(each_rb['node-rbridge-id'])
        if len(rb_list) >= 3:
            raise ValueError('VLAG PAIR must be <= 2 leaf nodes')
        return list(set(rb_list))
