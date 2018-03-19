# Copyright 2017 Brocade Communications Systems, Inc.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import time
import paramiko
import socket
from ipaddress import ip_address
from ne_base import capture_exceptions
from st2common.runners.base_action import Action
from pyswitch.snmp.snmpconnector import SnmpConnector as SNMPDevice
from pyswitch.snmp.snmpconnector import SNMPError as SNMPError
from pyswitch.snmp.SnmpMib import SnmpMib as MIB
from pyswitch.XMLAsset import XMLAsset
from pyswitchlib.exceptions import (RestInterfaceError, RestProtocolTypeError)


class RegisterDeviceCredentials(Action):

    """
       Implements the logic for registering the device
       credentials into st2 store. Other NE action can
       retrieve the device credentials from this store,
       Especially the SNMP credentials have lot of inputs
       and all those information will be stored.
       This action achieves the following functionality:
            - Add/update device credentials into st2store
    """

    def __init__(self, config=None, action_service=None):
        super(
            RegisterDeviceCredentials,
            self).__init__(
            config=config,
            action_service=action_service)
        self.host = None
        self.ostype = 'unknown'
        self.snmpconfig = {}
        self.devcredentials = None

    @capture_exceptions
    def run(self, mgmt_ip, username, password, enable_password, snmp_port,
            snmp_version, snmp_v2c, snmpv3_user, snmpv3_auth,
            auth_pass, snmpv3_priv, priv_pass, rest_protocol):

        try:
            ip_address(mgmt_ip)
        except Exception as err:
            self.logger.error("Invalid IP address: %s", mgmt_ip)
            raise AttributeError(err.message)

        devprefix = self._get_lookup_prefix(mgmt_ip)
        self.devcredentials = self.action_service.list_values(local=False, prefix=devprefix)

        if snmp_version == 'v2':
            self.snmpconfig['snmpver'] = snmp_version
            self.snmpconfig['snmpv2c'] = snmp_v2c
            self.snmpconfig['snmpport'] = snmp_port
            self.snmpconfig['v3user'] = None
            self.snmpconfig['v3priv'] = None
            self.snmpconfig['v3auth'] = None
            self.snmpconfig['authpass'] = None
            self.snmpconfig['privpass'] = None
        elif snmp_version == 'v3':
            self.snmpconfig['snmpv2c'] = None
            self.snmpconfig['snmpver'] = snmp_version
            self.snmpconfig['snmpport'] = snmp_port
            self.snmpconfig['v3user'] = snmpv3_user
            self.snmpconfig['v3priv'] = snmpv3_priv
            self.snmpconfig['v3auth'] = snmpv3_auth
            if auth_pass:
                self.snmpconfig['authpass'] = auth_pass
            else:
                self.snmpconfig['authpass'] = ''
            if priv_pass:
                self.snmpconfig['privpass'] = priv_pass
            else:
                self.snmpconfig['privpass'] = ''

        if not rest_protocol:
            rest_protocol = 'http'

        self._validate_input_credentials(mgmt_ip, username, password, enable_password,
                                         rest_protocol)

        if self.devcredentials:
            # update case as already exists for this device
            self._update_device(mgmt_ip, username, password, enable_password,
                                rest_protocol)
        else:
            self._register_device(mgmt_ip, username, password, enable_password,
                                  rest_protocol)

    def _get_lookup_key(self, host, lookup):
        return 'switch.%s.%s' % (host, lookup)

    def _get_lookup_prefix(self, host):
        return 'switch.%s.' % host

    def _validate_input_credentials(self, host, user=None, passwd=None, enable_pass=None,
                                    rest_proto=None):

        """
           Method to validate user input for device credentials
           Input Params:
                host       : Device management IP address
                user       : Username for ssh/cli login
                passwd     : Password for ssh/cli login
                enable_pass: Privilege Exec Password
                rest_proto : REST protocol used for REST requests

           Return Value:
        """

        if self.snmpconfig:
            # Validate snmpv2 credentials
            if self.snmpconfig['snmpver'] == 'v2':
                v2c = self.snmpconfig['snmpv2c']
                if not v2c or v2c == '':
                    self.logger.error("SNMP v2 community missing ( --snmp_v2c= )")
                    sys.exit(-1)
            elif self.snmpconfig['snmpver'] == 'v3':
                auth = self.snmpconfig['v3auth']
                priv = self.snmpconfig['v3priv']
                if auth != "noauth":
                    if not self.snmpconfig['authpass']:
                        self.logger.error("Auth passphrase missing (--auth_pass= )")
                        sys.exit(-1)
                if auth == 'noauth':
                    if self.snmpconfig['authpass']:
                        self.logger.error("param (--auth_pass) should be\
                                           empty if snmpv3_auth  is noauth")
                        sys.exit(-1)
                if priv == 'nopriv':
                    if self.snmpconfig['privpass']:
                        self.logger.error("param (--priv_pass) should be\
                                           empty if snmpv3_priv  is noauth")
                        sys.exit(-1)
                if priv != "nopriv":
                    if not self.snmpconfig['privpass']:
                        self.logger.error("Priv passphrase missing (--priv_pass= )")
                        sys.exit(-1)
                pass

        # if host == 'USER.DEFAULT':
        #    return

        if user and passwd:
            self.ostype = self._validate_ssh_connection(host, user, passwd)

        if self.ostype == 'ni':
            self.logger.warning("Skip REST protocol storage for this device")

            ret = self._validate_snmp_credentials(host)
            if not ret:
                sys.exit(-1)

        if self.ostype == 'slx' or self.ostype == 'nos':
            self.logger.warning("Skip SNMP credentials storage for this device")

            if enable_pass:
                self.logger.warning("Skip enable password storage for this device")

            if rest_proto:
                ret = self.rest_proto = self._validate_rest_connection(host, user, passwd,
                                                                       rest_proto)
                if not ret:
                    sys.exit(-1)

        return

    def _validate_snmp_credentials(self, host):

        """
           Method to validate snmp credentials
           Input Params:
                host: Device management IP address
           Return Value:
                True - if snmp credential is successful
                False - if snmp credential is not successful
        """

        if not self.snmpconfig:
            self.logger.error("This device requires SNMP credentials")
            sys.exit(-1)

        config = self.snmpconfig

        if 'snmpver' in config:
            if config['snmpver'] == 'v2':
                version = 2
                v2c = config['snmpv2c']
                user = ''
                authproto = ''
                privproto = ''
                authpass = ''
                privpass = ''
            elif config['snmpver'] == 'v3':
                version = 3
                v2c = ''
                user = config['v3user']
                authproto = config['v3auth']
                privproto = config['v3priv']
                authpass = config['authpass']
                privpass = config['privpass']

        try:
            snmp = SNMPDevice(host=host, port=config['snmpport'],
                              version=version,
                              community=v2c,
                              username=user,
                              authproto=authproto,
                              authkey=authpass,
                              privproto=privproto,
                              privkey=privpass)
            snmp.get(MIB.mib_oid_map['sysObjectId'])
        except SNMPError as error:
            self.logger.error("SNMP Engine Error: %s", error)
            self.logger.error("Verify your SNMP credentials")
            return False
        return True

    def _validate_ssh_connection(self, host, user, passwd):

        """
            Method to validate ssh cli connection and obtain os_version
            Input Params:
                 host       : Device management IP address
                 user       : Username for ssh/cli login
                 passwd     : Password for ssh/cli login

            Return Value:
                 "ni", "slx", "nos", "unknown"
        """

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, username=user, password=passwd)
        except paramiko.BadHostKeyException:
            self.logger.error("Bad Host key error")
            sys.exit(-1)
        except paramiko.AuthenticationException:
            self.logger.error("Authentication failed while connecting to %s", host)
            sys.exit(-1)
        except paramiko.SSHException as error:
            self.logger.error("Remote connection error: %s", error)
            sys.exit(-1)
        except socket.error as error:
            self.logger.error("Socket connection Error: %s", error)
            sys.exit(-1)

        channel = client.invoke_shell()
        # VDX/SLX banner takes sometime
        time.sleep(5)
        channel.send("terminal length 0\n")
        channel.recv(100)
        channel.send("\n")
        channel.send("show chassis\n")
        time.sleep(5)
        out = channel.recv(500000)
        data = out.split("show chassis\r\n")
        client.close()

        ostype = 'unknown'

        sdata = data[1].split("\r\n")
        for item in sdata:
            if "BR-VDX" in item:
                ostype = 'nos'
                return ostype
            elif "BR-SLX" in item:
                ostype = 'slx'
                return ostype
            elif "MLXe" in item or "NetIron" in item:
                ostype = 'ni'
                return ostype

        return ostype

    def _validate_rest_connection(self, host, user, passwd, rest_proto):

        """
            Method to validate ssh cli connection and obtain os_version
            Input Params:
                 host       : Device management IP address
                 user       : Username for rest login
                 passwd     : Password for rest login
                 rest_proto : Protocol used for rest requests

            Return Value:
                 True - if rest connection using the specified rest_proto
                        is successful
                 False - if rest connection using the specified rest_proto
                         is not successful
        """

        asset = None
        enabled_protocols = []

        try:
            asset = XMLAsset(ip_addr=host, auth=(user, passwd),
                             rest_proto=rest_proto)
        except RestProtocolTypeError as error:
            self.logger.error("Rest Protocol Type Error: %s", error)
            return False
        except RestInterfaceError as error:
            self.logger.error("Rest Interface Error: %s", error)
            return False

        enabled_protocols = asset.get_enabled_rest_protocols()

        if self.ostype == 'unknown':
            self.ostype = asset.get_os_type()

        if enabled_protocols:
            if rest_proto not in enabled_protocols:
                self.logger.error("Specified rest protocol: %s is not enabled on the device.",
                                  rest_proto)
                return False
        else:
            self.logger.error("Failed to retrieve enabled rest protocols.")
            return False

        return True

    def _update_device(self, host, user, passwd, enablepass, restproto):
        """
          Method to update the device credentials. While update
          if user has not specified any existing values then it will
          be removed.
        """
        self.logger.info("Updating credentials for the given device")

        if self.snmpconfig:
            snmpport = self.snmpconfig['snmpport']
            snmpver = self.snmpconfig['snmpver']
            snmpv2c = self.snmpconfig['snmpv2c']
            v3user = self.snmpconfig['v3user']
            v3auth = self.snmpconfig['v3auth']
            authpass = self.snmpconfig['authpass']
            v3priv = self.snmpconfig['v3priv']
            privpass = self.snmpconfig['privpass']
        else:
            snmpver = snmpv2c = v3user = None
            v3auth = v3priv = None
            authpass = privpass = None
            snmpport = None

        if self.ostype == 'slx' or self.ostype == 'nos':
            snmpver = 'None'
            enablepass = None
        else:
            if self.ostype != 'unknown':
                restproto = None

        is_snmpver_set = False
        is_snmpport_set = False
        is_enablepass_set = False
        is_restproto_set = False

        # For encrypted values we are overwriting the values
        # since it involves another get_value query.

        for item in self.devcredentials:

            lookup_key = item.name

            if lookup_key == self._get_lookup_key(host, 'user') and user:
                if user != item.value:
                    self.action_service.set_value(name=lookup_key,
                                                  value=user, local=False)
            elif lookup_key == self._get_lookup_key(host, 'passwd') and passwd:
                self.action_service.set_value(name=lookup_key, value=passwd,
                                              local=False, encrypt=True)
            elif lookup_key == self._get_lookup_key(host, 'enablepass') and enablepass:
                is_enablepass_set = True
                self.action_service.set_value(name=lookup_key, value=enablepass,
                                              local=False, encrypt=True)
            elif lookup_key == self._get_lookup_key(host, 'restproto') and restproto:
                is_restproto_set = True
                if restproto != item.value:
                    self.action_service.set_value(name=lookup_key,
                                                  value=restproto, local=False)
            elif lookup_key == self._get_lookup_key(host, 'ostype') and self.ostype:
                if self.ostype != item.value:
                    self.action_service.set_value(name=lookup_key, value='unknown',
                                                  local=False)
            elif lookup_key == self._get_lookup_key(host, 'snmpver') and snmpver:
                is_snmpver_set = True
                if snmpver != item.value:
                    self.action_service.set_value(name=lookup_key, value=snmpver,
                                                  local=False)
            elif lookup_key == self._get_lookup_key(host, 'snmpport') and snmpport:
                is_snmpport_set = True
                if snmpport != int(item.value):
                    self.action_service.set_value(name=lookup_key, value=snmpport,
                                                  local=False)
            else:
                # lookup key found but user input is not present hence removing
                self.action_service.delete_value(name=item.name, local=False)

        # This is a case for USER.DEFAULT
        if enablepass and is_enablepass_set is False:
            lookup_key = self._get_lookup_key(host, 'enablepass')
            self.action_service.set_value(name=lookup_key, value=enablepass,
                                          local=False, encrypt=True)

        # This is a case for USER.DEFAULT
        if restproto and is_restproto_set is False:
            lookup_key = self._get_lookup_key(host, 'restproto')
            self.action_service.set_value(name=lookup_key, value=restproto, local=False)

        # This is a case for USER.DEFAULT
        if is_snmpver_set is False:
            lookup_key = self._get_lookup_key(host, 'snmpver')
            if snmpver is None:
                self.action_service.set_value(name=lookup_key, value='None', local=False)
            else:
                self.action_service.set_value(name=lookup_key, value=snmpver, local=False)

        if snmpver and snmpver != 'None' and is_snmpport_set is False:
            lookup_key = self._get_lookup_key(host, 'snmpport')
            if snmpport is None:
                self.action_service.set_value(name=lookup_key, value=161, local=False)
            else:
                self.action_service.set_value(name=lookup_key, value=snmpport, local=False)

        if snmpv2c and snmpver == 'v2':
            lookup_key = self._get_lookup_key(host, 'snmpv2c')
            self.action_service.set_value(name=lookup_key, value=snmpv2c,
                                         local=False, encrypt=True)

        if v3user and snmpver == 'v3':
            lookup_key = self._get_lookup_key(host, 'v3user')
            self.action_service.set_value(name=lookup_key,
                                          value=v3user, local=False)
        if v3auth and snmpver == 'v3':
            lookup_key = self._get_lookup_key(host, 'v3auth')
            self.action_service.set_value(name=lookup_key,
                                          value=v3auth, local=False)
        if v3priv and snmpver == 'v3':
            lookup_key = self._get_lookup_key(host, 'v3priv')
            self.action_service.set_value(name=lookup_key,
                                          value=v3priv, local=False)
        if authpass and snmpver == 'v3':
            lookup_key = self._get_lookup_key(host, 'authpass')
            self.action_service.set_value(name=lookup_key, value=authpass,
                                          local=False, encrypt=True)
        if privpass and snmpver == 'v3':
            lookup_key = self._get_lookup_key(host, 'privpass')
            self.action_service.set_value(name=lookup_key, value=privpass,
                                          local=False, encrypt=True)

    def _store_value(self, host, key, value, encrypt=False):
        """
          Wrapper method to set the value in keystore
          Input Params:
               host  : Device ip or special host
               key   : key string to form lookup_key
               value : value to set
               encrypt:
                    True - Encrypt values while storing
                    False - Don't encrypt values
          Return values:
        """
        lookup_key = self._get_lookup_key(host=host, lookup=key)
        self.action_service.set_value(name=lookup_key, value=value,
                                      local=False, encrypt=encrypt)

    def _register_device(self, host, user, passwd, enable_pass=None, rest_proto=None):
        """
           This method store the device credentials into st2 store
        """
        self.logger.info("Adding device credentials for first time")

        if user:
            self._store_value(host=host, key='user', value=user)

        if passwd:
            self._store_value(host=host, key='passwd', value=passwd, encrypt=True)

        self._store_value(host=host, key='ostype', value=self.ostype)

        snmp_ver = 'None'
        # if self.ostype == 'ni' or host == 'USER.DEFAULT':
        if self.ostype == 'ni':
            if enable_pass:
                self._store_value(host=host, key='enablepass', value=enable_pass, encrypt=True)

            if self.snmpconfig:
                snmp_port = self.snmpconfig['snmpport']
                snmp_ver = self.snmpconfig['snmpver']
                snmp_v2c = self.snmpconfig['snmpv2c']
                v3user = self.snmpconfig['v3user']
                v3auth = self.snmpconfig['v3auth']
                authpass = self.snmpconfig['authpass']
                v3priv = self.snmpconfig['v3priv']
                privpass = self.snmpconfig['privpass']

            self._store_value(host=host, key='snmpver', value=snmp_ver)

            if snmp_ver != 'None':
                self._store_value(host=host, key='snmpport', value=snmp_port)

            if snmp_ver == 'v2' and snmp_v2c != '':
                self._store_value(host=host, key='snmpv2c', value=snmp_v2c, encrypt=True)

            if snmp_ver == 'v3':
                self._store_value(host=host, key='v3user', value=v3user)
                self._store_value(host=host, key='v3auth', value=v3auth)
                self._store_value(host=host, key='v3priv', value=v3priv)
                self._store_value(host=host, key='authpass', value=authpass, encrypt=True)
                self._store_value(host=host, key='privpass', value=privpass, encrypt=True)

            # if rest_proto and host == 'USER.DEFAULT':
            #    self._store_value(host=host, key='restproto', value=rest_proto)

        else:
            self._store_value(host=host, key='snmpver', value='None')

            if rest_proto:
                self._store_value(host=host, key='restproto', value=rest_proto)
