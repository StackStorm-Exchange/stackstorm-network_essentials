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

import sys

from ne_base import NosDeviceAction
from ne_base import capture_exceptions
from ne_base import ValidateErrorCodes


class CheckPing(NosDeviceAction):

    """
    Implements the logic to check if ping is passing or failing for an ip or list of ips
    """

    @capture_exceptions
    def run(self, mgmt_ip, username, password, targets, count, timeout_value, vrf, size):

        ping_output = []
        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as e:
            self.logger.error(e.message)
            sys.exit(-1)

        # pylint: disable=no-member
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            (status, ping_output) = device.utils.ping(targets=targets, count=count,
                                                      timeout_value=timeout_value,
                                                      vrf=vrf, size=size)
            result = {}
            rcode = ValidateErrorCodes.SUCCESS
            result['reason_code'] = rcode.value
            result['ping_output'] = ping_output
            return (status, result)
