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
import re
import json
from ipaddress import ip_address
from ipaddress import ip_interface
from st2actions.runners.pythonrunner import Action
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, \
    NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException


class CheckPing(Action):
    """
    Implements the logic to check if ping is passing or failing for an ip or list of ips
    """
    def create_ping_cmd(self, targets, vrf, count, timeout_value, size):
        cli_cmd = []
        try:
            for numips in targets:
                check_valid_ip = ip_address(unicode(numips))
                numips = str(check_valid_ip)
                valid_address = ip_interface(unicode(numips))

                if valid_address.version == 4:
                    cli = "ping {} vrf {} count {} datagram-size {} timeout {}".format(
                        numips, vrf, count, size, timeout_value)
                elif valid_address.version == 6:
                    cli = "ping ipv6 {} vrf {} count {} datagram-size {} timeout {}".format(
                        numips, vrf, count, size, timeout_value)
                cli_cmd.append(cli)
            return cli_cmd
        except ValueError:
            self.logger.error('Invalid IP')
            return False

    def execute_cli(self, opt, cli_list):
        cli_output = {}
        try:
            net_connect = ConnectHandler(**opt)
            for cmd in cli_list:
                cmd = cmd.strip()
                cli_output[cmd] = (net_connect.send_command(cmd))
                self.logger.info('successfully executed cli %s', cmd)
        except (NetMikoTimeoutException, NetMikoAuthenticationException,) as e:
            reason = e.message
            self.logger.error('Failed to execute cli on %s due to %s', opt['ip'], reason)
            raise ValueError('Failed to execute cli on %s due to %s', opt['ip'], reason)

        except SSHException as e:
            reason = e.message
            self.logger.error('Failed to execute cli on %s due to %s', opt['ip'], reason)
            raise ValueError('Failed to execute cli on %s due to %s', opt['ip'], reason)
        except Exception as e:
            reason = e.message
            # This is in case of I/O Error, which could be due to
            # connectivity issue or due to pushing commands faster than what
            #  the switch can handle
            self.logger.error('Failed to execute cli on %s due to %s', opt['ip'], reason)
            raise ValueError('Failed to execute cli on %s due to %s', opt['ip'], reason)
        finally:
            if not net_connect:
                net_connect.disconnect()
        return cli_output

    def run(self, mgmt_ip, username, password, targets, count, timeout_value, vrf, size):
        ipv4_address = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        ipv6_address = re.compile('(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:'
                                  '[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]'
                                  '{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9]'
                                  '[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]'
                                  '{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]'
                                  '{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4]'
                                  '[0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]'
                                  '{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]'
                                  '{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]'
                                  '{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9]'
                                  '[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.)'
                                  '{3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4]'
                                  '[0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]'
                                  '{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]'
                                  '{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9]'
                                  '[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.)'
                                  '{3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4]'
                                  '[0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:)'
                                  '{,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:)'
                                  '{2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|'
                                  '[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}'
                                  '(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|'
                                  '(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]'
                                  '{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|'
                                  '(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.)'
                                  '{3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))'
                                  '|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:'
                                  '[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9]'
                                  '[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|'
                                  '[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:'
                                  '[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]'
                                  '{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)')
        cli_list = self.create_ping_cmd(targets, vrf, count, timeout_value, size)

        opt = {'device_type': 'brocade_vdx'}
        opt['ip'] = mgmt_ip
        opt['username'] = username
        opt['password'] = password
        opt['verbose'] = True
        opt['global_delay_factor'] = 0.5
        cli_output = self.execute_cli(opt, cli_list)

        failed_ips_list = []
        success_ips_list = []
        final_output = []
        for key, value in cli_output.iteritems():
            output_dict = {}
            if ipv4_address.search(key):
                ip = ipv4_address.search(key).group()
            elif ipv6_address.search(key):
                ip = ipv6_address.search(key).group()
            value_list = value.splitlines()
            for i, line in enumerate(value_list):
                if line.startswith('--- ' + ip):

                    p_tx = re.search(r'(\d+)(\spackets\stransmitted)',
                                     str(value_list[i + 1])).group(1)
                    p_rx = re.search(r'(\d+)(\spackets\sreceived)',
                                     str(value_list[i + 1])).group(1)
                    p_loss = re.search(r'(\d+)(\%)(\spacket\sloss)',
                                       str(value_list[i + 1])).group(1)
                    if 100 >= int(p_loss) > 0:
                        print "Failed to ping to %s" % str(ip)
                        failed_ips_list.append(str(ip))
                        output_dict['ip_address'] = str(ip)
                        output_dict['result'] = 'fail'
                        output_dict['packets transmitted'] = p_tx
                        output_dict['packets received'] = p_rx
                        output_dict['packet loss'] = p_loss + "%"
                    elif int(p_loss) == 0:
                        print "Successful ping to %s" % str(ip)
                        success_ips_list.append(str(ip))
                        output_dict['ip_address'] = ip
                        output_dict['result'] = 'pass'
                        output_dict['packets transmitted'] = p_tx
                        output_dict['packets received'] = p_rx
                        output_dict['packet loss'] = p_loss + "%"
            final_output.append(output_dict)
        json_outputformat = json.dumps(
            final_output, sort_keys=True, indent=4, separators=(',', ': '))
        return json_outputformat
