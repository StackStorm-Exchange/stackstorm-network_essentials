from ne_base import NosDeviceAction
from ne_base import log_exceptions


class Remove_Acl(NosDeviceAction):
    def run(self, mgmt_ip, username, password, intf_type, intf_name,
            rbridge_id, acl_name, acl_direction, traffic_type):
        """Run helper methods to remove ACL on desired interface.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        return self.switch_operation(intf_type, intf_name,
                                     rbridge_id, acl_name,
                                     acl_direction, traffic_type)

    @log_exceptions
    def switch_operation(self, intf_type, intf_name,
                         rbridge_id, acl_name, acl_direction, traffic_type):
        interface_list = []
        intf_type = intf_type.lower()

        # Check is the user input for Interface Name is correct
        for intf in intf_name:
            if "-" not in str(intf):
                interface_list.append(intf)
            else:
                ex_intflist = self.extend_interface_range(intf_type=intf_type, intf_name=intf)
                for ex_intf in ex_intflist:
                    interface_list.append(ex_intf)

        with self.pmgr(conn=self.conn,
                       auth_snmp=self.auth_snmp, connection_type='NETCONF') as device:
            address_type = device.acl.get_acl_type(acl_name)['protocol']
            for intf in interface_list:
                if not self.validate_interface(intf_type, str(intf),
                                               rbridge_id=rbridge_id,
                                               os_type=device.os_type):
                    raise ValueError("Input is not a valid Interface")

                return self._remove_acl(device, address_type=address_type,
                                        intf_type=intf_type,
                                        intf_name=interface_list,
                                        rbridge_id=rbridge_id,
                                        acl_name=acl_name,
                                        acl_direction=acl_direction,
                                        traffic_type=traffic_type)

    def _remove_acl(self, device, address_type, intf_type, intf_name, rbridge_id,
                    acl_name, acl_direction, traffic_type):
        result = {}
        for intf in intf_name:
            self.logger.info('Removing ACL %s on int-type - %s int-name- %s',
                             acl_name, intf_type, intf)

            output = device.acl.remove_acl(rbridge_id=rbridge_id, address_type=address_type,
                                           intf_type=intf_type, intf=intf,
                                           acl_name=acl_name, acl_direction=acl_direction,
                                           traffic_type=traffic_type)
            self.logger.info(output)
            result[intf] = True
        return result
