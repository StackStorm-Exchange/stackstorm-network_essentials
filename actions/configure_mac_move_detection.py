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
import sys


class ConfigureMacMoveDetection(NosDeviceAction):
    """
       Implements the logic to configure Mac Move Enable and limit on VDX switches
       This action acheives the below functionality
           Check for the existing configuration on the Device,if not present configure it
    """

    def run(self, mgmt_ip, username, password, move_threshold):
        """Run helper methods to implement the desired state.
        """
        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as e:
            self.logger.error(e.message)
            sys.exit(-1)
        changes = {}
        if move_threshold > 500 or move_threshold < 5:
            raise ValueError('Mac Move Threshold is Invalid. Not in <5-500> range')
        move_threshold = str(move_threshold)
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info('successfully connected to %s', self.host)
            changes['conv-arp'] = self._configure_mac_move_detection(device,
                                                                  limit=move_threshold)
            self.logger.info('closing connection to %s after configuring mac move detect'
                             ' enable and limit-- all done!', self.host)
        return changes

    def _configure_mac_move_detection(self, device, limit):
        """Configuring  Mac Move Enable and threshold under config mode.
        """
        is_mac_move_detect = True
        is_move_threshold = True
        try:
            mac_move = device.interface.mac_move_detect_enable(get=True)
        except NotImplementedError as e:
            self.logger.error("Mac move enable failed %s" % (e.message))
            sys.exit(-1)
        if mac_move is not None:
            self.logger.info('Mac Move detect enable already configured')
            is_mac_move_detect = False
        else:
            self.logger.info('Configuring Mac Move Detect Enable')
            device.interface.mac_move_detect_enable()
        mac_move = device.interface.mac_move_detect_enable(get=True)
        if mac_move is not None:
            move_limit = device.interface.mac_move_limit(get=True)
            if move_limit == "20" and limit == "20":
                self.logger.info('Default Mac Move threshold %s already configured',
                                 move_limit)
                is_move_threshold = False
            elif move_limit == limit:
                self.logger.info('Mac Move threshold %s already configured',
                                 move_limit)
                is_move_threshold = False
            else:
                self.logger.info('Configuring Mac Move threshold %s on the Switch',
                                 limit)
                device.interface.mac_move_limit(mac_move_limit=limit)

        if not is_mac_move_detect:
            return False

        if not is_move_threshold:
            return False
        return True
