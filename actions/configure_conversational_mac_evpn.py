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


class ConfigureConversationalMacEvpn(NosDeviceAction):
    """
       Implements the logic to configure converstaional mac on VDX switches
       This action acheives the below functionality
           Check for the existing configuration on the Device,if not present configure it
    """

    def run(self, host, user, passwd):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=host, user=user, passwd=passwd)
        changes = {}
        with self.mgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s', self.host)
            changes['conv-mac'] = self._configure_conversational_mac_evpn(device)
            self.logger.info('closing connection to %s after configuring conversational mac '
                             '-- all done!', self.host)
        return changes

    def _configure_conversational_mac_evpn(self, device):
        """Configuring converstaional mac under config mode.
        """
        conv_mac = device.interface.conversational_mac(get=True)
        if conv_mac is not None:
            self.logger.info('Converstaional Mac already configured')
            return False
        else:
            self.logger.info('Configuring Conversational Mac')
            device.interface.conversational_mac()
        return True
