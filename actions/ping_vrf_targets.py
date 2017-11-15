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


class CheckPing(NosDeviceAction):

    """
    Implements the logic to check if ping is passing or failing for an ip or list of ips
    """

    def run(self, mgmt_ip, username, password, targets, count, timeout_value, vrf, size):

        ping_output = []
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)

        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            ping_output = device.utils.ping(targets=targets, count=count,
                                           timeout_value=timeout_value, vrf=vrf, size=size)
        return ping_output
