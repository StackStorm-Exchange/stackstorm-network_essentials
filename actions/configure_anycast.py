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


class ConfigureAnycast(NosDeviceAction):
    """Implements logic to affect an anycast gateway change on VDX switches.
    """

    un_supported_model = 'VDX8770'

    def run(self, mgmt_ip, rbridge_id, mac, username=None, password=None):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}
        with self.mgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s', self.host)
            self._check_requirements(device, rbridge_id)
            changes['disable_vrrp'] = self._disable_vrrp(device, rbridge_id)
            changes['configure_anycast_mac'] = self._configure_anycast_mac(device, rbridge_id, mac)
            self.logger.info('closing connection to %s -- all done!', self.host)
        return changes

    def _check_requirements(self, device, rbridge_id):
        """Fail the task if device is unsupported.
        """
        device_model = device.system.chassis_name(rbridge_id=rbridge_id)

        if self.un_supported_model in device_model:
            msg = 'cannot configure anycastmac on %s' % device_model
            raise ValueError(msg)

    def _disable_vrrp(self, device, rbridge_id):
        """Disable VRRP
        """
        changed = False
        for ip_version in ['4', '6']:
            try:
                device.services.vrrp(enabled=False, ip_version=ip_version,
                                     rbridge_id=rbridge_id)
                changed = True
            except:
                self.logger.info('VRRP already disabled on %s for IPv%s', self.host, ip_version)
        return changed

    def _configure_anycast_mac(self, device, rbridge_id, mac):
        """Configure Anycast Gateway MAC
        """
        opts = dict(get=True, rbridge_id=rbridge_id, mac=mac)
        conf = device.interface.anycast_mac(**opts)
        conf = conf.data.find('.//{*}anycast-gateway-mac')
        mac_already_configured = conf.text == mac if conf else False
        if mac_already_configured:
            return False
        self.logger.info('configuring anycast MAC (%s) on %s', mac, self.host)
        del opts['get']
        device.interface.anycast_mac(**opts)
        return True
