import sys
import re
from ne_base import NosDeviceAction


class CreateAcl(NosDeviceAction):
    """
    Creating mac ipv4 and ipv6 ACLs
    """

    def run(self, mgmt_ip, username, password, address_type, acl_type, acl_name):
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}
        device = self.get_device()
        changes = self._create_acl(device, address_type, acl_type, acl_name)
        return changes

    def _create_acl(self, device, address_type, acl_type, acl_name):
        msg_reg_exp = re.compile(r'\{\'error-string\'\:\s\'([^\']+)')
        create = []
        result = None
        if not any([acl_type == 'extended', acl_type == 'standard']):
            self.logger.error('Invalid acl_type %s', acl_type)
            return result
        method = '{}_access_list_{}_create'.format(address_type, acl_type)
        create_acl = eval('device.{}'.format(method))
        self.logger.info('Creating %s ACL %s of type %s',
                         address_type, acl_name, acl_type)
        try:
            create = create_acl(acl_name)
            result = create[0]
            if not result:
                pyswitch_error = create[1][0][self.host]['response']['json']['output']
                pyswitch_error = str(create[1][0][self.host]['response']['json']['output'])
                if 'object already exists' in pyswitch_error:
                    self.logger.info('%s already present', acl_name)
                else:
                    self.logger.error('Cannot create ACL %s due to %s', acl_name,
                                      pyswitch_error)
                    sys.exit(-1)
            else:
                self.logger.info('Successfully created ACL %s in %s', acl_name, self.host)
        except (KeyError, ValueError, AttributeError) as e:
            error = msg_reg_exp.search(e.message)
            if error:
                error = error.group(1)
            self.logger.error('Cannot create ACl %s due to %s', acl_name, error)
            sys.exit(-1)
        return result
