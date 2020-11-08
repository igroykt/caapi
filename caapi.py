import os
import sys
import subprocess
import configparser

class CAApi:
    server = ""
    user = ""
    remote_tmp = ""
    local_storage = ""
    ca_name = ""
    cert_template = ""

    def __init__(self, server, user, remote_tmp, local_storage, ca_name, cert_template):
        self.server = server
        self.user = user
        self.remote_tmp = remote_tmp
        self.local_storage = local_storage
        self.ca_name = ca_name
        self.cert_template = cert_template

    def call(self, command):
	    process = subprocess.Popen(command,stdout = subprocess.PIPE,stderr = subprocess.PIPE, shell = True, universal_newlines = True, errors = "ignore")
	    std_out,std_err = process.communicate()
	    return process.returncode, std_out, std_err

    def ssh(self, cmd):
        try:
            code, out, err = self.call(f"ssh -o 'StrictHostKeyChecking no' {self.user}@{self.server} '{cmd}'")
            return out.strip()
        except Exception as e:
            return e

    def scp_put(self, source, destination):
        try:
            self.call(f"scp -o 'StrictHostKeyChecking no' {source} {self.user}@{self.server}:{destination}")
            return True
        except Exception as e:
            return e

    def scp_get(self, source, destination):
        try:
            self.call(f"scp -o 'StrictHostKeyChecking no' {self.user}@{self.server}:{source} {destination}")
            return True
        except Exception as e:
            return e

    '''def get_domain_netbios(self):
        try:
            out = self.ssh("echo %USERDOMAIN%")
            return out
        except Exception as e:
            return e

    def get_domain_hostname(self):
        try:
            out = self.ssh("hostname")
            return out
        except Exception as e:
            return e'''


    def generate_config_for(self, user_fullname, user_dn, user_mail, user_domain):
        dn = user_dn.split("@")
        requester = dn[0]
        config = configparser.ConfigParser()
        config['Version'] = {
            'Signature': '"$Windows NT$"'
        }
        config['NewRequest'] = {
            'Subject': f'"CN={user_fullname}"',
            'KeyLength': '2048',
            'KeySpec': '1',
            'KeyUsage': '0xa0',
            'ProviderName' : '"Microsoft RSA SChannel Cryptographic Provider"',
            'ProviderType': '1',
            'RequestType': 'CMC',
            'RequesterName': f'"{user_domain}\{requester}"',
        }
        config['RequestAttributes'] = {
            'CertificateTemplate': f'{self.cert_template}'
        }
        config['Extensions'] = {
            '2.5.29.17': '"{text}"',
            '_continue_': f'"email={user_mail}&"'
        }
        try:
            with open(f'/tmp/{requester}.ini', 'w') as configfile:
                config.write(configfile)
            self.call(f"sed -i '$ d' /tmp/{requester}.ini")
            self.call(f"echo '_continue_ = \"upn={user_dn}&\"' >> /tmp/{requester}.ini")
            return True
        except Exception as e:
            return e

    def generate_cert_for(self, user_dn, cep_cert, cert_pass):
        try:
            dn = user_dn.split("@")
            requester = dn[0]
            self.scp_put(f"/tmp/{requester}.ini, {self.remote_tmp}")
            self.ssh(f"certreq -f -new -config {hostname}\{self.ca_name} {self.remote_tmp}\\{requester}.ini {self.remote_tmp}\\{requester}.req")
            self.ssh(f"certreq -f -q -config {hostname}\{self.ca_name} -sign -cert {cep_cert} {self.remote_tmp}\\{requester}.req {self.remote_tmp}\\{requester}_signed.req")
            self.ssh(f"certreq -submit -config {hostname}\{self.ca_name} -attrib 'CertificateTemplate: {self.cert_template}' {self.remote_tmp}\\{requester}_signed.req {self.remote_tmp}\\{requester}.cer")
            self.ssh(f"certutil -addstore -f MY {self.remote_tmp}\\{requester}.cer")
            self.ssh(f"certutil -repairstore MY {user_dn}")
            self.ssh(f"certutil -p {cert_pass} -exportPFX {user_dn} {self.remote_tmp}\\{requester}.pfx")
            self.ssh(f"certutil -privatekey –delstore MY {user_dn}")
            self.scp_get(f"{self.remote_tmp}\\{requester}.pfx, {self.local_storage}")
            self.ssh(f"del /F /Q {self.remote_tmp}\\{requester}.cer {self.remote_tmp}\\{requester}.ini {self.remote_tmp}\\{requester}.pfx {self.remote_tmp}\\{requester}.req {self.remote_tmp}\\{requester}.rsp {self.remote_tmp}\\{requester}_signed.req")
            return True
        except Exception as e:
            return e