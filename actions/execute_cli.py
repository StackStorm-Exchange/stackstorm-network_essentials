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
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, \
    NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException
import sys

from ne_base import NosDeviceAction


class CliCMD(NosDeviceAction):
    """
       Implements the logic to find MACs on an interface on VDX Switches .
    """

    def run(self, mgmt_ip, username, password, cli_cmd, device_type='brocade_vdx'):
        """Run helper methods to implement the desired state.
        """
        result = {}
        op_result = self.execute_cli_command(mgmt_ip, username, password, cli_cmd, device_type)
        if op_result is not None:
            result = op_result
        return result

    def execute_cli_command(self, mgmt_ip, username, password, cli_cmd, device_type='brocade_vdx'):
        opt = {'device_type': device_type}
        opt['ip'] = mgmt_ip
        opt['username'] = username
        opt['password'] = password
        opt['verbose'] = True
        opt['global_delay_factor'] = 0.5
        net_connect = None
        cli_output = {}

        try:
            net_connect = ConnectHandler(**opt)
            self.logger.info('successfully connected to %s to find execute CLI %s', self.host,
                             cli_cmd)
            for cmd in cli_cmd:
                cmd = cmd.strip()
                cli_output[cmd] = (net_connect.send_command(cmd))
                self.logger.info('successfully executed cli %s', cmd)
            self.logger.info('closing connection to %s after executions cli cmds -- all done!',
                             self.host)
            return cli_output
        except (NetMikoTimeoutException, NetMikoAuthenticationException,
                ) as e:
            reason = e.message
            self.logger.error('Failed to execute cli on %s due to %s', mgmt_ip, reason)
            sys.exit(-1)
        except SSHException as e:
            reason = e.message
            self.logger.error('Failed to execute cli on %s due to %s', mgmt_ip, reason)
            sys.exit(-1)
        except Exception as e:
            reason = e.message
            # This is in case of I/O Error, which could be due to
            # connectivity issue or due to pushing commands faster than what
            #  the switch can handle
            self.logger.error('Failed to execute cli on %s due to %s', mgmt_ip, reason)
            sys.exit(-1)
        finally:
            if net_connect is not None:
                net_connect.disconnect()
