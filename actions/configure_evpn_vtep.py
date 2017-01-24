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
import re


class ConfigureEvpnVtep(NosDeviceAction):
    """
       Implements the logic to configure EVPN VTEP
       This action acheives the below functionality
           1.Loopback Id Validation
           2.Check for the existing configurations on the Device,
             if not present configure evpn vtep name, vni mapping
             type, loopback id, attach rbridge-id & activate it
    """

    def run(self, mgmt_ip, username, password, loopback_id, rbridge_id, name):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}
        if loopback_id > 255 or loopback_id < 1:
            raise ValueError('Loopback Id is Invalid. Not in <1-255> range')
        if len(name) > 32 or len(name) < 1:
            raise ValueError(
                'Overlay Gateway Name is Invalid. Not in <1-32> range')

        val_name = re.match("^[a-zA-Z0-9_-]*$", name)
        if not val_name:
            raise ValueError(
                'Input for Overlay Gateway name can contain only alphabets,'
                ' digits, hyphen or underscore')

        loopback_id = str(loopback_id)
        with self.mgr(conn=self.conn, auth=self.auth) as device:
            if rbridge_id is None:
                rb_list = self.vlag_pair(device)
            else:
                rb_list = rbridge_id

            if len(rb_list) == 2:
                rb_range = rb_list[0] + '-' + rb_list[1]
            else:
                rb_range = str(rb_list[0])

            self.logger.info('successfully connected to %s', self.host)
            changes['vtep'] = self._configure_evpn_vtep(device, name=name,
                                                        rbridge_id=rb_range,
                                                        loopback_id=loopback_id)
            self.logger.info(
                'closing connection to %s after configuring evpn vtep'
                '-- all done!', self.host)
        return changes

    def _configure_evpn_vtep(self, device, name, loopback_id, rbridge_id):
        """Configuring evpn vtep
        """

        result = True
        # Configuring Overlay Gateway Name
        vtep_name = device.interface.overlay_gateway_name(get=True)
        if vtep_name is not None:
            if vtep_name != name:
                raise ValueError('Overlay Gateway name is already configured',
                                 vtep_name)
            else:
                self.logger.info('Overlay Gateway Name %s already configured',
                                 vtep_name)
            result = False
        else:
            self.logger.info('Configuring Overlay Gateway Name %s', name)
            device.interface.overlay_gateway_name(gw_name=name)

        # Configuring Overlay Gateway Type
        gwtype = device.interface.overlay_gateway_type(get=True)
        if 'layer2-extension' in gwtype:
            self.logger.info(
                'Overlay Gateway Type %s already configured under %s',
                gwtype, vtep_name)
            result = False
        elif gwtype is None or 'layer2-extension' not in gwtype:
            self.logger.info(
                'Configuring Overlay Gateway Type Layer2-Extension')
            device.interface.overlay_gateway_type(gw_name=name,
                                                  gw_type='layer2-extension')

        # Configuring Map vlan VNI Auto
        vlan_vni_map = device.interface.overlay_gateway_vlan_vni_auto(get=True)
        if vlan_vni_map is None:
            self.logger.info('Configuring Vlan Vni Mapping to auto')
            device.interface.overlay_gateway_vlan_vni_auto(gw_name=name)
        else:
            self.logger.info(
                'Map vlan VNI auto is already configured Overlay Gateway %s',
                name)
            result = False

        # Configuring attach rbridge_id under Overlay Gateway
        attach_rb = device.interface.overlay_gateway_attach_rbridge_id(get=True)
        if attach_rb is None:
            self.logger.info('Configuring attach rbridge-id %s', rbridge_id)
            device.interface.overlay_gateway_attach_rbridge_id(gw_name=name,
                                                               rbridge_id=rbridge_id)
        elif attach_rb is not None and attach_rb != rbridge_id:
            self.logger.info('Configuring attach rbridge-id %s', rbridge_id)
            device.interface.overlay_gateway_attach_rbridge_id(gw_name=name,
                                                               rbridge_id=rbridge_id)
        else:
            self.logger.info('Attach rbridge-id %s is already configured under '
                             'Overlay Gateway %s', attach_rb, name)
            result = False

        # Configuring ip interface loopback under Overlay Gateway
        loopback = device.interface.overlay_gateway_loopback_id(get=True)
        if loopback is None:
            self.logger.info('Configuring loopback id %s', loopback_id)
            device.interface.overlay_gateway_loopback_id(gw_name=name,
                                                         loopback_id=loopback_id)
        else:
            self.logger.info('Loopback id %s is already configured under '
                             'Overlay Gateway %s', loopback, name)
            result = False

        # Activating the VTEP EVPN
        status = device.interface.overlay_gateway_activate(get=True)
        if status is None:
            self.logger.info('Activating Overlay Gateway %s', name)
            device.interface.overlay_gateway_activate(gw_name=name,
                                                      rbridge_id=rbridge_id)
        else:
            self.logger.info('Activate config is already configured under '
                             'Overlay Gateway %s', name)
            result = False

        return result
