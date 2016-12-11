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

from ne_base import NosDeviceAction


class CliCMD(NosDeviceAction):
    """
       Implements the logic to find MACs on an interface on VDX Switches .
    """

    def run(self, host, user, passwd, cli_cmd):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=host, user=user, passwd=passwd)
        result = {}
        self.logger.info('successfully connected to %s to find execute CLI %s', self.host, cli_cmd)
        result = self.execute_cli_command(host, user, passwd, cli_cmd)
        self.logger.info('closing connection to %s after executions cli cmds -- all done!',
                         self.host)
        return result

    def execute_cli_command(self, host, user, passwd, cli_cmd):
        opt = {'device_type': 'brocade_vdx'}
        opt['ip'] = host
        opt['username'] = user
        opt['password'] = passwd
        opt['verbose'] = True
        opt['global_delay_factor'] = 0.5
        net_connect = None
        cli_output = {}
        try:
            net_connect = ConnectHandler(**opt)
            for cmd in cli_cmd:
                cmd = cmd.strip()
                cli_output[cmd] = (net_connect.send_command(cmd))
                self.logger.info('successfully executed cli %s', cmd)
            return cli_output
        except (NetMikoTimeoutException, NetMikoAuthenticationException,
                ) as e:
            reason = e.message
            raise ValueError('Failed to execute cli on %s due to %s', host, reason)
        except SSHException as e:
            reason = e.message
            raise ValueError('Failed to execute cli on %s due to %s', host, reason)
        except Exception as e:
            reason = e.message
            # This is in case of I/O Error, which could be due to
            # connectivity issue or due to pushing commands faster than what
            #  the switch can handle
            raise ValueError('Failed to execute cli on %s due to %s', host, reason)
        finally:
            if net_connect is not None:
                net_connect.disconnect()
            return cli_output
