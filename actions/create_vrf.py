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
from ne_base import log_exceptions
from execute_cli import CliCMD


class CreateVRF(NosDeviceAction):

    """
       Implements the logic to Create a VRF  on VDX Switches .
       This action acheives the below functionality
           1. Create VRF
    """

    def run(self, mgmt_ip, username, password, vrf_name, rbridge_id, afi, rd):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}

        return self.switch_operation(afi, changes, rbridge_id, vrf_name, rd)

    @log_exceptions
    def switch_operation(self, afi, changes, rbridge_id, vrf_name, rd):
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:

            self.logger.info('successfully connected to %s to Create VRF '
                             'for tenants',
                             self.host)

            if rbridge_id:
                for rb_id in rbridge_id:
                    self.validate_supports_rbridge(device, rb_id)

                    validation_VRF = self._check_requirements_VRF(device, rb_id,
                                                                  vrf_name)
                    if validation_VRF:
                        changes['Create_VRF'] = self._create_VRF(device, rb_id,
                                                                 vrf_name)

                    validate_vrf_afi = self._validate_vrf_afi(device, rb_id,
                                                              vrf_name, afi)
                    if validate_vrf_afi:
                        changes['Create_address_family'] = self._create_vrf_afi(
                            device, rb_id,
                            vrf_name, afi)
                    self.logger.info('closing connection to %s after Create VRF '
                                     '- all done!',
                                     self.host)

                    if 'Create_VRF' in changes:
                        self._fetch_VRF_state(device, vrf_name)
            else:
                self.validate_supports_rbridge(device, rbridge_id)

                validation_VRF = self._check_requirements_VRF(device, rbridge_id,
                                                              vrf_name)
                if validation_VRF:
                    changes['Create_VRF'] = self._create_VRF(device, rbridge_id,
                                                             vrf_name)

                validate_vrf_afi = self._validate_vrf_afi(device, rbridge_id,
                                                          vrf_name, afi)
                if validate_vrf_afi:
                    changes['Create_address_family'] = self._create_vrf_afi(
                        device, rbridge_id,
                        vrf_name, afi, rd)
                self.logger.info('closing connection to %s after Create VRF '
                                 '- all done!',
                                 self.host)

                if 'Create_VRF' in changes:
                    self._fetch_VRF_state(device, vrf_name)
        return changes

    def _check_requirements_VRF(self, device, rbridge_id, vrf_name):
        """ pre-checks to identify the existing vrf configurations"""

        vrf_output = device.interface.vrf(get=True, rbridge_id=rbridge_id)
        if vrf_output is not None:
            for each_vrf in vrf_output:
                if each_vrf['vrf_name'] == vrf_name:
                    self.logger.info('VRF %s  already exists',
                                     vrf_name)
                    return False
        return True

    def _validate_vrf_afi(self, device, rbridge_id, vrf_name, afi):
        """ Pre-checks to identify VRF address family configurations"""
        afi_status = device.interface.vrf_afi(
            get=True, rbridge_id=rbridge_id, vrf_name=vrf_name)
        if afi_status[afi]:
            self.logger.info('VRF %s address family already configured for %s',
                             afi, vrf_name)
            return False
        return True

    def _create_vrf_afi(self, device, rbridge_id, vrf_name, afi, rd):
        """ Create Address Family """
        try:
            self.logger.info(
                'Creating %s address family for VRF %s ',
                afi,
                vrf_name)
            device.interface.vrf_afi(
                vrf_name=vrf_name, rbridge_id=rbridge_id, afi=afi, rd=rd)
        except (ValueError, KeyError) as e:
            error_message = str(e.message)
            self.logger.error(error_message)
            raise ValueError('Invalid Input types while creating %s address '
                             'family on VRF %s',
                             afi, vrf_name)
            return False
        return True

    def _create_VRF(self, device, rbridge_id, vrf_name):
        """ create VRF """

        try:
            self.logger.info('Creating VRF %s ', vrf_name)
            self.logger.info('vrf name type %s', type(vrf_name))
            self.logger.info('Rbridge id type %s', type(rbridge_id))
            device.interface.vrf(vrf_name=vrf_name, rbridge_id=rbridge_id)
        except (ValueError, KeyError) as e:
            error_message = str(e.message)
            self.logger.error(error_message)
            raise ValueError('Invalid Input types while creating VRF %s',
                             vrf_name)
        return True

    def _fetch_VRF_state(self, device, vrf_name):
        """validate DAI state.
        """

        exec_cli = CliCMD()
        host_ip = self.host
        host_username = self.auth[0]
        host_password = self.auth[1]
        cli_arr = []
        cli_cmd = 'show vrf ' + vrf_name
        cli_arr.append(cli_cmd)

        raw_cli_output = exec_cli.execute_cli_command(mgmt_ip=host_ip,
                                                      username=host_username,
                                                      password=host_password,
                                                      cli_cmd=cli_arr)
        output = str(raw_cli_output)
        self.logger.info(output)
        return True
