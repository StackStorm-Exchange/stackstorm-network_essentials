from ne_base import NosDeviceAction


class ValidateInterfaceVlanPy(NosDeviceAction):
    """
       Implements the logic to Validate port channel or physical interface and \
       mode belongs to a VLAN on VDX and SLX devices.
    """

    def run(self, mgmt_ip, username, password, vlan_id, intf_name, intf_mode):
        """Run helper methods to implement the desired state."""
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}

        try:
            device = self.asset(ip_addr=self.host, auth=self.auth)
            self.logger.info('successfully connected to %s to validate interface vlan', self.host)
        except AttributeError as e:
            changes["result"] = "False"
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
        # Check if the user input for VLANS is correct
        vlan_list = self.expand_vlan_range(vlan_id=vlan_id)
        if vlan_list:
            changes['vlan'] = self._validate_interface_vlan_py(device, vlan_list,
                                                               intf_name,
                                                               intf_mode)
        else:
            raise ValueError('Input is not a valid vlan')
        self.logger.info('closing connection to %s after configuring create vlan -- all done!',
                         self.host)
        return changes

    def _validate_interface_vlan_py(self, device, vlan_id, intf_name, intf_mode):
        """validate interface vlan .
        """
        is_vlan_interface_present = False
        is_intf_name_mode_present = False
        output = device.get_interface_switchport_rpc(None)
        try:
            intf_vlan_list = output[1][0][self.host]['response']['json']['output']['switchport']
        except:
            self.logger.error('No switchport configured')
            return False
        if type(intf_vlan_list) == dict:
            intf_vlan_list = [intf_vlan_list, ]
        for vlanid in vlan_id:
            vlanid = str(vlanid)
            for out in intf_vlan_list:
                try:
                    vid = out['active-vlans']['vlanid']
                except:
                    self.logger.error('No active VLAN associated with %s', vlan_id)
                    return False
                if vlanid in str(vid):
                    is_vlan_interface_present = True
                    if intf_name in out['interface-name'] and intf_mode in out['mode']:
                        is_intf_name_mode_present = True
                        self.logger.info("Successfully Validated port channel/physical "
                                         "interface %s and mode %s belongs to a VLAN %s",
                                         intf_name, intf_mode, vlanid)
                    else:
                        continue

        if not is_vlan_interface_present:
            self.logger.error("Vlan not exist on the device")
            return False
        if not is_intf_name_mode_present:
            self.logger.error("Invalid port channel/physical interface or mode belongs to a VLAN")
            return False

        return True
