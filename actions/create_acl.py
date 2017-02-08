from ne_base import NosDeviceAction


class CreateAcl(NosDeviceAction):
    """
    Creating mac ipv4 and ipv6 ACLs
    """

    def run(self, mgmt_ip, username, password, address_type, acl_type, acl_name):
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}
        try:
            device = self.asset(ip_addr=self.host, auth=self.auth)
            self.logger.info('successfully connected to %s to create ACL',
                             self.host)
        except AttributeError as e:
            self.logger.error('Failed to connect to %s due to %s', self.host, e.message)
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
        changes = self._create_acl(device, address_type, acl_type, acl_name)
        return changes

    def _create_acl(self, device, address_type, acl_type, acl_name):
        create = []
        result = {}
        if not any([acl_type == 'extended', acl_type == 'standard']):
            self.logger.error('Invalid acl_type %s', acl_type)
            return result
        method = '{}_access_list_{}_create'.format(address_type, acl_type)
        create_acl = eval('device.{}'.format(method))
        self.logger.info('Creating %s ACL %s of type %s',
                         address_type, acl_name, acl_type)
        try:
            create = create_acl(acl_name)
            if not create[0]:
                self.logger.error('Cannot create ACL %s due to %s', acl_name,
                                  str(create[1][0][self.host]['response']['json']['output']))
            else:
                self.logger.info('Successfully created ACL %s in %s', acl_name, self.host)
        except (KeyError, ValueError, AttributeError) as e:
            self.logger.error('Cannot create ACl %s due to %s', acl_name, e.message)
            raise ValueError(e.message)
        result['result'] = create[0]
        return result
