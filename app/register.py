#!/usr/bin/env python3

# Copyright (c) 2018, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import sys
import os
import logging
import json
import requests
import urllib
import ipaddress

try:
    from config import *
except ImportError:
    print ("Run setup.py")
    sys.exit(0)

from pandevice import device
from pandevice import firewall
from pandevice import panorama

from var_dump import var_dump

class Register:
    """Class for registering a fresh deployed PanOS firewall VM

    """
    
    url = 'https://api.paloaltonetworks.com/'
    url_get = url+'api/license/get'
    url_activate = url+'api/license/activate'

    def __init__(self, ip):
        self.ip = ip
        
        self.alreadylicensed = False

        global fw_api_username, fw_api_password, api

        self.logging = logging.getLogger(__name__)

        self.username = fw_api_username
        self.password = fw_api_password
        self.api = api

        self.fw = firewall.Firewall(self.ip, self.username, self.password)

        self.get_vm_infos()

        self.is_registered()
        
        self.select_auth_code()
        
        self.get_auth_code_info()
        
        if self.alreadylicensed == False:
            self.register_vm()
        else:
            self.get_license_vm()
        
        #self.store_lic()
        #self.push_license_to_vm()

    def is_registered(self):
        """Get the CPUID and UUID of the VM

        """

        self.logging.info("Check if already registered")

        self.ip

        #raise

    def get_vm_infos(self):
        """Get the CPUID and UUID of the VM

        """

        self.logging.info("Get the CPUID and UUID of the VM")

        try:
            
            resp = self.fw.op("show system info")

            for t in resp.iter('hostname'):
                self.hostname = t.text

            for t in resp.iter('vm-uuid'):
                self.uuid = t.text

            for t in resp.iter('vm-cpuid'):
                self.cpuid = t.text

            self.logging.debug("VM Hostname: {}".format(self.hostname))
            self.logging.debug("VM CPUID: {}".format(self.cpuid))
            self.logging.debug("VM UUID: {}".format(self.uuid))
        
        except:
            self.logging.debug("Error when reaching Firewall")
            raise
    
    def select_auth_code(self):
        """Select the proper auth code according to the IP subnet or Hostname

        """
        global authcode

        self.authcode = authcode
    
    def get_auth_code_info(self):
        """Select the proper auth code according to the IP subnet or Hostname

        """
        global authcode

        self.authcode = authcode
        
        data = { 
            "authCode": self.authcode
        }

        headers = {'apikey': self.api, 'user-agent': 'PANW-Lic-API/0.1.0'}

        req = requests.Request( 'POST', self.url_get, headers=headers, json=data )
        p = req.prepare()
        s = requests.Session()
        r = s.send(p)

        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            self.logging.debug("Can't get the VM with the autcode {}.\n See the message {}".format(authcode, e.response._content))
            raise e
        except:
            self.logging.debug("Can't register the VM with the autcode {}.\n See the message {}".format(authcode, e.response._content))
            self.logging.debug("Error when reaching API License Server")
            raise

        data = r.json()
        
        self.extract_get_answer(data)

    def extract_get_answer(self, data):
        """Extract Licenses, AuthCode, SerialNumber from Support answer

        """
        self.devices = dict()
        
        for devices in data['UsedDeviceDetails']:
            
            if devices['UUID'] == self.uuid and \
               devices['CPUID'] == self.cpuid:
                
                self.alreadylicensed = True
                self.serialnumber = devices['SerialNumber']
                self.logging.debug("this VM is already licensed in CSP portal")

    def get_license_vm(self):
        """Extract licence for the VM to the support portal within CPUID and UUID

        """

        self.logging.info("Extract licence for the VM to the support portal within CPUID and UUID to the support API portal")

        data = { 
            "serialNumber": self.serialnumber
        }

        headers = {'apikey': self.api, 'user-agent': 'PANW-Lic-API/0.1.0'}

        req = requests.Request( 'POST', self.url_activate, headers=headers, json=data )
        p = req.prepare()
        s = requests.Session()
        r = s.send(p)

        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            self.logging.debug("Can't extract the VM with the serialnumber {}.\n See the message {}".format(serialnumber, e.response._content))
            raise e
        except:
            self.logging.debug("Can't extract the VM with the serialnumber {}.\n See the message {}".format(serialnumber, e.response._content))
            self.logging.debug("Error when reaching API License Server")
            raise

        data = r.json()

        self.extract_lic_answer(data)

    def register_vm(self):
        """Register the VM to the support portal within CPUID and UUID

        """

        self.logging.info("Register the VM with CPUID and UUID to the support API portal")

        data = { 
            "cpuid": self.cpuid, 
            "uuid": self.uuid, 
            "authCode": self.authcode
        }

        headers = {'apikey': self.api, 'user-agent': 'PANW-Lic-API/0.1.0'}

        req = requests.Request( 'POST', self.url_activate, headers=headers, json=data )
        p = req.prepare()
        s = requests.Session()
        r = s.send(p)

        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            self.logging.debug("Can't register the VM with the autcode {}.\n See the message {}".format(authcode, e.response._content))
            raise e
        except:
            self.logging.debug("Can't register the VM with the autcode {}.\n See the message {}".format(authcode, e.response._content))
            self.logging.debug("Error when reaching API License Server")
            raise

        data = r.json()

        self.extract_lic_answer(data)

    def extract_lic_answer(self, data):
        """Extract Licenses, AuthCode, SerialNumber from Support answer

        """
        self.licenses = dict()
        self.authcode = dict()

        for lic in data:

            if lic['featureField'] == ('AutoFocus Device License'):
                lName = "PAN-VM-AUTOFOCUS"
            else:
                lName = lic['partidField']

            if lic['auth_codeField']:
                self.authcode[lName] = lic['auth_codeField']

            if lic['serialnumField']:
                self.serialnumField = lic['serialnumField']

            self.licenses[lName] = lic['keyField']

    def store_lic(self):
        """Store license files

        """

        self.logging.info("Store license files")

        for key, value in self.licenses.items():
            fName = "./licenses/"+self.serialnumField+"/"+key+".lic"
            self.write_lic_file(fName, value)

    def push_license_to_vm(self):
        """Push license to the VM

        """

        self.logging.info("Push license to the VM")

        try:

            for key, value in self.licenses.items():
                self.logging.debug("Push license {}".format(key))

                req = "<request><license><install>"
                req += value
                req += "</install></license></request>"

                self.fw.op(req, cmd_xml=False)
                self.logging.debug("OK")
        
        except:
            self.logging.debug("Unable to push license to the PanOS Firewall")
            raise

        self.logging.info("Firewall will restart just after the license push. Wait him.")
        self.fw.syncreboot()

        self.logging.info("Refresh informations and test connectivity")
        self.fw.refresh_system_info()
            
    def get_serialnumber(self):
        """Extract VM serial number from the API support portal answer

        """
        return self.serialnumField

    def write_lic_file(self, filename, keyField):
        """Write license file in a license directory

        """

        self.logging.debug("Storing {}".format(filename))

        try:
            os.makedirs(os.path.dirname(filename), exist_ok=True)
        except:
            self.logging.debug("File directory doesn't exist or cannot be created")

        try:
            f = open(filename,"w")
            f.write(keyField)
            f.close()
        except:
            self.logging.debug("File cannot be created")
            raise
