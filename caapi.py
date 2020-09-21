import os
import sys
import subprocess

class CAApi:
    server = ""
    user = ""

    def __init__(self, server, user):
        self.server = server
        self.user = user

    def call(self, command):
	    process = subprocess.Popen(command,stdout = subprocess.PIPE,stderr = subprocess.PIPE,shell = True, universal_newlines = True)
	    std_out,std_err = process.communicate()
	    return process.returncode, std_out, std_err

    def test(self, cmd):
        code, out, err = self.call(f"ssh {self.user}@{self.server} '{cmd}'")
        if out:
            return out
        return False