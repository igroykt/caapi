import os
import sys
import subprocess
import configparser
from OpenSSL import crypto

class CAApi:
    server = ""
    user = ""
    remote_tmp = ""
    cert_template = ""

    def __init__(self, server, user, remote_tmp, cert_template):
        self.server = server
        self.user = user
        self.remote_tmp = remote_tmp
        self.cert_template = cert_template

    def call(self, command):
	    process = subprocess.Popen(command,stdout = subprocess.PIPE,stderr = subprocess.PIPE,shell = True, universal_newlines = True)
	    std_out,std_err = process.communicate()
	    return process.returncode, std_out, std_err

    def ssh(self, cmd):
        try:
            code, out, err = self.call(f"ssh -o 'StrictHostKeyChecking no' {self.user}@{self.server} '{cmd}'")
            return out.strip()
        except Exception as e:
            return e

    def scp(self, file):
        try:
            self.call(f"scp -o 'StrictHostKeyChecking no' {file} {self.user}@{self.server}:{self.remote_tmp}")
            return True
        except Exception as e:
            return e

    def get_domainnetbios(self):
        try:
            out = self.ssh("echo %USERDOMAIN%")
            return out
        except Exception as e:
            return e

    def generate_config(self, requester):
        short_domain = self.get_domainnetbios()
        config = configparser.ConfigParser()
        config['Version'] = {
            'Signature': '"$Windows NT$"'
        }
        config['NewRequest'] = {
            'Subject': f'"CN={requester}"',
            'KeySpec': '1',
            'KeyLength': '2048',
            'Exportable': 'true',
            'MachineKeySet': 'true',
            'SMIME': 'false',
            'PrivateKeyArchive': 'false',
            'UserProtected': 'false',
            'UseExistingKeySet': 'false',
            'ProviderName': '"Microsoft RSA SChannel Cryptographic Provider"',
            'ProviderType': '12',
            'RequestType': 'CMC',
            'RequesterName': f'"{short_domain}\{requester}"',
            'KeyUsage': '0xa0'
        }
        config['RequestAttributes'] = {
            'CertificateTemplate': self.cert_template
        }
        config['EnhancedKeyUsageExtension'] = {
            # server authentication OID
            'OID': '1.3.6.1.5.5.7.3.1',
            # client authentication OID
            'OID': '1.3.6.1.5.5.7.3.2'
        }
        try:
            with open(f'/tmp/{requester}.ini', 'w') as configfile:
                config.write(configfile)
                return True
        except Exception as e:
            return e

    def request_cert(self, requester):
        try:
            self.call(f"openssl req -sha256 -key /tmp/{requester}.key -new -out /tmp/{requester}.csr -config /tmp/{requester}.ini")
            self.scp(f"{requester}.ini {requester}.csr")
            return True
        except Exception as e:
            return e