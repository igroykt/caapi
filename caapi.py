import os
import sys
import subprocess
import configparser
import os.path

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
        destination = destination.replace("\\", "\\\\")
        try:
            self.call(f"scp -o 'StrictHostKeyChecking no' {source} {self.user}@{self.server}:{destination}")
            return True
        except Exception as e:
            return e

    def scp_get(self, source, destination):
        source = source.replace("\\", "\\\\")
        try:
            self.call(f"scp -o 'StrictHostKeyChecking no' {self.user}@{self.server}:{source} {destination}")
            return True
        except Exception as e:
            return e

    def generate_config(self, user_fullname, user_pname, user_mail, user_domain):
        pname = user_pname.split("@")
        requester = pname[0]
        if os.path.isfile(f"/tmp/{requester}.ini"):
            os.remove(f"/tmp/{requester}.ini")
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
            self.call(f"echo '_continue_ = \"upn={user_pname}&\"' >> /tmp/{requester}.ini")
            if os.path.isfile(f"/tmp/{requester}.ini"):
                return True
            return False
        except Exception as e:
            return e

    def generate_payload(self, user_pname, cert_pass, cep_cert):
        pname = user_pname.split("@")
        requester = pname[0]
        if os.path.isfile(f"/tmp/{requester}.bat"):
            os.remove(f"/tmp/{requester}.bat")
        f = open(f"/tmp/{requester}.bat", "a")
        f.write(f"certreq -f -new -config {self.ca_name} {self.remote_tmp}\\{requester}.ini {self.remote_tmp}\\{requester}.req\r\n")
        f.write(f"certreq -f -q -config {self.ca_name} -sign -cert {cep_cert} {self.remote_tmp}\\{requester}.req {self.remote_tmp}\\{requester}_signed.req\r\n")
        f.write(f"certreq -f -submit -config {self.ca_name} -attrib CertificateTemplate:{self.cert_template} {self.remote_tmp}\\{requester}_signed.req {self.remote_tmp}\\{requester}.cer\r\n")
        f.write(f"certutil -addstore -f MY {self.remote_tmp}\\{requester}.cer\r\n")
        f.write(f"certutil -repairstore MY {user_pname}\r\n")
        f.write(f"certutil -p {cert_pass} -exportPFX {user_pname} {self.remote_tmp}\\{requester}.pfx\r\n")
        f.write(f"certutil -privatekey -delstore MY {user_pname}")
        f.close()
        if os.path.isfile(f"/tmp/{requester}.bat"):
            return True
        return False

    def generate_cert(self, user_pname, cert_pass, cep_cert):
        pname = user_pname.split("@")
        requester = pname[0]
        try:
            self.scp_put(f"/tmp/{requester}.ini", self.remote_tmp)
            payload = self.generate_payload(user_pname, cert_pass, cep_cert)
            if payload:
                self.scp_put(f"/tmp/{requester}.bat", self.remote_tmp)
                self.ssh(f"{self.remote_tmp}\\{requester}.bat")
                if not os.path.isdir(self.local_storage):
                    os.mkdir(self.local_storage)
                self.scp_get(f"{self.remote_tmp}\\{requester}.pfx", f"{self.local_storage}")
                self.ssh(f"del /F /Q {self.remote_tmp}\\{requester}.bat {self.remote_tmp}\\{requester}.cer {self.remote_tmp}\\{requester}.ini {self.remote_tmp}\\{requester}.pfx {self.remote_tmp}\\{requester}.req {self.remote_tmp}\\{requester}.rsp {self.remote_tmp}\\{requester}_signed.req")
                self.call(f"rm -f /tmp/{requester}.bat /tmp/{requester}.ini")
                return True
            return False
        except Exception as e:
            return e

    def revoke_cert(self, user_pname, cert_pass, reason):
        pname = user_pname.split("@")
        requester = pname[0]
        try:
            if os.path.isfile(f"/tmp/{requester}.cer"):
                os.remove(f"/tmp/{requester}.cer")
            self.call(f"openssl pkcs12 -in {self.local_storage}/{requester}.pfx -out /tmp/{requester}.cer -nokeys -clcerts -passin pass:{cert_pass}")
            code, out, err = self.call(f"openssl x509 -noout -serial -in /tmp/{requester}.cer")
            out = out.split("=")
            serial = out[1]
            self.ssh(f"certutil -config {self.ca_name} -revoke \"{serial}\" {reason}")
            self.call(f"rm -f /tmp/{requester}.cer {self.local_storage}/{requester}.pfx")
            if not os.path.isfile(f"{self.local_storage}/{requester}.pfx"):
                return True
            return False
        except Exception as e:
            return e