from ne_base import NosDeviceAction


class DeleteAcl(NosDeviceAction):
    """
    Deleting ipv4 and ipv6 ACL's
    """
    def run(self, mgmt_ip, username, password, acl_name):
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}
        try:
            device = self.asset(ip_addr=self.host, auth=self.auth)
            self.logger.info('successfully connected to %s to delete ACL',
                             self.host)
        except AttributeError as e:
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
        self.logger.info('getting the ACL type from device.')
        get_acl = self._get_acl_type_(device, acl_name)
        if get_acl:
            acl_type = get_acl['type']
            self.logger.info('successfully identified the acl_type as %s', acl_type)
            changes = self._delete_acl(device, acl_type, acl_name)
        else:
            self.logger.info('Failed to identify acl_type. Check if the ACL %s exists', acl_name)
            changes = None
        return changes

    def _delete_acl(self, device, acl_type, acl_name):
        delete = []
        result = {}
        if acl_type == 'extended':
            atype = 'extended'
        elif acl_type == 'standard':
            atype = 'standard'
        method = 'ip_access_list_{}_delete'.format(atype)
        dl_acl = eval('device.{}'.format(method))
        self.logger.info('Deleting ACL %s', acl_name)
        try:
            delete = dl_acl(acl_name)
            if not delete[0]:
                self.logger.info('Cannot delete ACL %s due to %s', acl_name,
                                 str(delete[1][0][self.host]['response']['json']['output']))
            else:
                self.logger.info('Successfully deleted ACL %s from %s', acl_name, self.host)
        except (KeyError, ValueError, AttributeError) as e:
            self.logger.info('Cannot delete ACl %s due to %s', acl_name, e.message)
            raise ValueError(e.message)
        result['result'] = delete[0]
        return result
