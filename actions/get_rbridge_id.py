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


class GetRbridgeId(NosDeviceAction):
    """
       Implements the logic to get rbridge id from given interface name.
       This action acheives the below functionality
    """

    def run(self, intf_name):
        """Run helper methods to implement the desired state.
        """

        rbridge = self._get_rbridge_id(intf_name=intf_name)
        return rbridge

    def _get_rbridge_id(self, intf_name):
        """get rbridge id from inf name.
        """

        rb_list = []
        for intf in intf_name:
            rb_id = self.get_rbridge_id(intf_name=intf)
            if not rb_id:
                raise ValueError('Input is not a valid rbridge-id')
            rb_list.append(str(rb_id))

        return rb_list
