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


class GetOsVersion(NosDeviceAction):
    """
       Implements the logic to get OS version of a devise.
       This action achieves the below functionality
           1.Get OS + Firmware version
    """

    def run(self, mgmt_ip, username, password):
        """Run helper methods to implement the desired state."""
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        version = {}

        try:
            device = self.asset(ip_addr=self.host, auth=self.auth)
            self.logger.info('successfully connected to %s to enable interface', self.host)
        except AttributeError as e:
            self.logger.info('Failed to connect to %s due to %s', self.host, e.message)
            raise ValueError('Failed to connect to %s due to %s', self.host, e.message)
        except ValueError as verr:
            self.logger.error("Error while logging in to %s due to %s",
                              self.host, verr.message)
            raise ValueError("Error while logging in to %s due to %s",
                             self.host, verr.message)
        except self.ConnectionError as cerr:
            self.logger.error("Connection failed while logging in to %s due to %s",
                              self.host, cerr.message)
            raise ValueError("Connection failed while logging in to %s due to %s",
                             self.host, cerr.message)
        except self.RestInterfaceError as rierr:
            self.logger.error("Failed to get a REST response while logging in "
                              "to %s due to %s", self.host, rierr.message)
            raise ValueError("Failed to get a REST response while logging in "
                             "to %s due to %s", self.host, rierr.message)

        version["result"] = self._get_os(device)
        self.logger.info('Closing connection to %s after finding OS -- all done!',
                         mgmt_ip)

        return version

    def _get_os(self, device):

        check_os = device.get_os_full_version()
        return check_os
