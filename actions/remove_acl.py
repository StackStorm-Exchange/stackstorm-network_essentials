import sys
from ne_base import NosDeviceAction


class Remove_Acl(NosDeviceAction):
    def run(self, mgmt_ip, username, password, intf_type, intf_name,
            rbridge_id, acl_name, acl_direction, traffic_type):
        """Run helper methods to remove ACL on desired interface.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        output = {}
        changes = []
        interface_list = []
        intf_type = intf_type.lower()
        device = self.get_device()
        ag_type = self._get_acl_type_(device, acl_name)['protocol']
        self.logger.info('successfully identified the access group type as %s', ag_type)
        # Check is the user input for Interface Name is correct
        for intf in intf_name:
            if "-" not in str(intf):
                interface_list.append(intf)
            else:
                ex_intflist = self.extend_interface_range(intf_type=intf_type, intf_name=intf)
                for ex_intf in ex_intflist:
                    interface_list.append(ex_intf)
        msg = None
        with self.pmgr(conn=self.conn, auth=self.auth) as device1:
            os = device1.os_type
        for intf in interface_list:
            if os == 'nos':
                if not self.validate_interface(intf_type, str(intf), rbridge_id):
                    msg = "Input is not a valid Interface"
                    self.logger.error(msg)
                    raise ValueError(msg)
            else:
                if not self.validate_interface(intf_type, str(intf), os_type=os):
                    msg = "Input is not a valid Interface"
                    self.logger.error(msg)
                    raise ValueError(msg)
        if msg is None:
            changes = self._remove_acl(device, intf_type=intf_type,
                                       intf_name=interface_list,
                                       rbridge_id=rbridge_id,
                                       acl_name=acl_name,
                                       acl_direction=acl_direction,
                                       ag_type=ag_type,
                                       traffic_type=traffic_type)
        output['result'] = changes
        self.logger.info('closing connection to %s after removing access-list-- all done!',
                         self.host)
        return output

    def _remove_acl(self, device, intf_type, intf_name, rbridge_id,
                    acl_name, acl_direction, ag_type, traffic_type):
        result = []
        for intf in intf_name:
            method = 'rbridge_id_interface_{}_{}_access_group_delete'. \
                format(intf_type, ag_type) if rbridge_id \
                else 'interface_{}_{}_access_group_delete'.format(intf_type, ag_type)

            rmve_acl = eval('device.{}'.format(method))
            access_grp = (acl_name, acl_direction, traffic_type)
            self.logger.info('Removing ACL %s on int-type - %s int-name- %s',
                             acl_name, intf_type, intf)
            try:
                rmve = list(rmve_acl(rbridge_id, intf, access_grp)
                            if rbridge_id else list(rmve_acl(intf, access_grp)))
                result.append(str(rmve[0]))
                if not rmve[0]:
                    self.logger.error('Cannot remove  %s on interface %s %s due to wrong intf_name'
                                      '/acl_direction/no acl configured on that interface',
                                      acl_name, intf_type, intf)
                    sys.exit(-1)
                else:
                    self.logger.info('Successfully  removed  %s ACL on interface %s %s ',
                                     acl_name, intf_type, intf)
            except (AttributeError, ValueError) as e:
                self.logger.error('Cannot remove %s on interface %s %s due to %s',
                                  acl_name, intf_type, intf, e.message)
                raise ValueError(e.message)
        return result
