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
from threading import Timer


class Firmware(NosDeviceAction):
    """
    Implements the logic to download firmware on the switch and
    check status.

    """
    fwdl_monitor_timer = None
    last_proc_fwdl_entry = 0
    fwdl_complete = False

    def run(self, mgmt_ip, username, password, host_ip, protocol_type,
            proto_username, proto_password, disruptive_download, firmware_path):

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)

        return self.switch_operation(host_ip, protocol_type,
            proto_username, proto_password, disruptive_download, firmware_path)

    @log_exceptions
    def switch_operation(self, host_ip, protocol_type, proto_username, proto_password,
                         disruptive_download, firmware_path):
        try:
            with self.pmgr(conn=self.conn, auth=self.auth) as device:
                self.logger.info('successfully connected to %s to download firmware', self.host)
                fwdl_status_dictlist = device.firmware.download_firmware(
                    protocol=protocol_type,
                    host=host_ip,
                    user_name=proto_username,
                    password=proto_password,
                    coldboot=disruptive_download,
                    directory=firmware_path,
                    os_type=device.os_type)

                num_entries = 0
                num_success = 0
                for fwdl_status_dict in fwdl_status_dictlist:
                    num_entries += 1
                    if device.os_type is 'nos':
                        self.logger.info("Rbridge:%d Download Status code: %d Status message:%s",
                                         fwdl_status_dict['rbridge-id'],
                                         fwdl_status_dict['status_code'],
                                         fwdl_status_dict['status_msg'])
                    else:
                        self.logger.info("Download Status code: %d Status message:%s",
                              fwdl_status_dict['status_code'],
                              fwdl_status_dict['status_msg'])
                    if fwdl_status_dict['status_code'] == 0:
                        num_success += 1

                if num_entries == num_success:
                    """
                    firmware download successful. Start Monitor process
                    """
                    self.last_proc_fwdl_entry = 0
                    self.fwdl_monitor_timer = \
                        Timer(30, lambda: self.firmware_download_monitor_periodic())
                    self.fwdl_monitor_timer.start()
                else:
                    self.logger.info("Firmware download failed, not starting monitoring")
        except Exception, exc:
            self.logger.info('Not able to connect to switch: %s', exc.message)

    def firmware_download_monitor_periodic(self):
        try:
            with self.pmgr(conn=self.conn, auth=self.auth) as device:
                self.fwdl_monitor_timer = None
                fwdl_status_list = device.firmware.firmware_download_monitor()
                for fwdl_status in fwdl_status_list:
                    index = fwdl_status['index']
                    if index <= self.last_proc_fwdl_entry:
                        continue
                    else:
                        self.last_proc_fwdl_entry = index
                        self.logger.info("Index: %d Blade:%s Time:%s Message:%s", index,
                                         fwdl_status['blade-name'],
                                         fwdl_status['timestamp'], fwdl_status['message'])
                        if fwdl_status['message'] == 'Firmware is downloaded successfully.':
                            self.logger.info("All done. Process complete")
                            self.fwdl_complete = True
                        else:
                            pass
                if self.fwdl_complete is True:
                    self.last_proc_fwdl_entry = 0
                    self.fwdl_monitor_timer = None
                else:
                    self.fwdl_monitor_timer = \
                        Timer(30, lambda: self.firmware_download_monitor_periodic())
                    self.fwdl_monitor_timer.start()
        except Exception, exc:
            self.logger.info('Exception while getting device: %s', exc.message)
            self.fwdl_monitor_timer = \
                Timer(30, lambda: self.firmware_download_monitor_periodic())
            self.fwdl_monitor_timer.start()












