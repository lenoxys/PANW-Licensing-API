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

try:
    from config import *
except ImportError:
    for arg in sys.argv: 1
# use the command line to call the function from a single script.
    print ("Run setup.py")
    sys.exit(0)

from pandevice import device
from pandevice import firewall
from pandevice import panorama

from var_dump import var_dump

class Register:
    """Class for registering a fresh deployed PanOS firewall VM

    """

   url = 'https://api.paloaltonetworks.com/api/license/activate'

   def __init__(self, ip):
      self.ip = ip

      global fw.api_username, fw.api_password

      self.username = fw.api_username
      self.password = fw.api_password

      self.fw.= firewall.Firewall(self.ip, self.username, self.password)

      self.get_vm_infos(self)
      self.

    def get_vm_infos(self):
        """Get the CPUID and UUID of the VM

        """

        logging.info("Get the CPUID and UUID of the VM")

        try:
            
            resp = self.self.fw.op("show system info")

            for t in resp.iter('vm-hostname'):
                self.hostname = t.text

            for t in resp.iter('vm-uuid'):
                self.uuid = t.text

            for t in resp.iter('vm-cpuid'):
                self.cpuid = t.text

            logging.debug("VM Hostname: {}".format(self.hostname))
            logging.debug("VM CPUID: {}".format(self.cpuid))
            logging.debug("VM UUID: {}".format(self.uuid))
        
        except:
            logging.debug("Error when reaching Firewall")
    
    def select_auth_code(self):
        """Select the proper auth code according to the IP subnet or Hostname

        """

    def push_license_to_vm(self):
        """Push license to the VM

        Args:
            r: string in json format containing all the license
            self.fw.hostname: hostname of the VM to login with API
            self.fw.api_username: username of the VM to login with API
            self.fw.api_password: password of the VM to login with API

        Returns:
            None

        """

        logging.info("Push license to the VM")

        try:

            for lic in self.licenses:
                logging.debug("Push license {}".format(lic['featureField']))

                req = "<request><license><install>"
                req += lic['keyField']
                req += "</install></license></request>"

                self.fw.op(req, cmd_xml=False)
                logging.debug("OK")
        
        except:
            logging.debug("Unable to push license to the PanOS Firewall")
            raise

        logging.info("Firewall will restart just after the license push. Wait him.")
        self.fw.syncreboot()

        logging.info("Refresh informations and test connectivity")
        self.fw.refresh_system_info()

    def register_vm(self):
        """Register the VM to the support portal within CPUID and UUID

        Args:
            cpuid: CPUID of the VM
            uuid: UUID of the VM 

        Returns:
            r: string in json format containing all the license

        """

        logging.info("Register the VM with CPUID and UUID to the support API portal")

        data = { 
            "cpuid": self.cpuid, 
            "uuid": self.uuid, 
            "authCode": self.authcode
        }

        headers = {'apikey': api, 'user-agent': 'PANW-Lic-API/0.1.0'}

        try:
            r = requests.post(self.url, headers=headers, json=data )
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logging.debug("Can't register the VM with the autcode {}.\n See the message {}".format(authcode, e.response._content))
            raise e
        except:
            logging.debug("Error when reaching API License Server")
            raise
        else:
            self.extract_license(self, r.json)

    def extract_license(self, r):


    def store_lic(self):
        """Extract Licenses and store it

        Args:
            r: Response from the API Support Portal 
            serialnumField: Firewall serial number 

        Returns:
            bolean: True if all license has been writen or False if something wrong append

        """

        logging.info("Extract Licenses and store it")

        if r == None:
            logging.debug("Nothing to process")
            return False

        for lic in r:

            try:
                fName = "./licenses/"+serialnumField+"/"
                if lic['featureField'] == ('AutoFocus Device License'):
                    fName += "PAN-VM-autofocus.key"
                else:
                    fName += lic['partidField']+".key"
                write_lic_file(fName, lic['keyField'])
            except:
                logging.debug('Problem to store lic in the filesystem')
                return False
        
        return True

        
    def get_authcodes(r = None):
        """Extract VM auth code from the API support portal answer

        Args:
            r: Response from the API Support Portal 

        Returns:
            list: authcodes or False if something wrong append

        """

        logging.debug("Extract VM auth code from the API support portal answer")

        if r == None:
            logging.debug("Nothing to process")
            return False

        auth_codeField = []

        for lic in r:
            try:
                if lic['auth_codeField']:
                    auth_codeField.append(lic['auth_codeField'])
            except:
                logging.debug('Problem to store lic in the filesystem')
                return False

        return auth_codeField
        
    def get_serialnumber(self):
        """Extract VM serial number from the API support portal answer

        Args:
            r: Response from the API Support Portal

        Returns:
            string: SerialNumber of the VM or False if something wrong append

        """

        logging.debug("Process License File and store it")

        if r == None:
            logging.debug("Nothing to process")
            return False

        serialnumField = None

        for lic in r:
            try:
                if lic['serialnumField']:
                    serialnumField = lic['serialnumField']
            except:
                logging.debug('Problem to store lic in the filesystem')
                return False

        return serialnumField

    def write_lic_file(self):
        """Write license file in a license directory

        Args:
            filename: filename

        Returns:
            None

        """

        try:
            os.makedirs(os.path.dirname(filename), exist_ok=True)
        except:
            logging.debug("File directory doesn't exist or cannot be created")

        try:
            f = open(filename,"w")
            f.write(keyField)
            f.close()
        except:
            logging.debug("File cannot be created")
            raise


