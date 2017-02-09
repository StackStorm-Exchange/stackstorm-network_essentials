import sys
from ne_base import NosDeviceAction


class DeleteAcl(NosDeviceAction):
    """
    Deleting ipv4 and ipv6 ACL's
    """
    def run(self, mgmt_ip, username, password, acl_name):
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}
        device = self.get_device()
        self.logger.info('getting the ACL type from device.')
        get_acl = self._get_acl_type_(device, acl_name)
        if get_acl:
            acl_type = get_acl['type']
            address_type = get_acl['protocol']
            self.logger.info('successfully identified the acl_type as %s and %s', acl_type,
                             address_type)
            changes = self._delete_acl(device, address_type, acl_type, acl_name)
        else:
            self.logger.error('Failed to identify acl_type. Check if the ACL %s exists', acl_name)
            sys.exit(-1)
        return changes

    def _delete_acl(self, device, address_type, acl_type, acl_name):
        delete = []
        result = None
        method = '{}_access_list_{}_delete'.format(address_type, acl_type)
        dl_acl = eval('device.{}'.format(method))
        self.logger.info('Deleting ACL %s', acl_name)
        try:
            delete = dl_acl(acl_name)
            if not delete[0]:
                self.logger.error('Cannot delete ACL %s due to %s', acl_name,
                                  str(delete[1][0][self.host]['response']['json']['output']))
                sys.exit(-1)
            else:
                self.logger.info('Successfully deleted ACL %s from %s', acl_name, self.host)
        except (KeyError, ValueError, AttributeError) as e:
            self.logger.error('Cannot delete ACl %s due to %s', acl_name, e.message)
            raise ValueError(e.message)
        result = delete[0]
        return result
