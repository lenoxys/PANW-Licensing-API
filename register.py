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

url = 'https://api.paloaltonetworks.com/api/license/activate'

def get_vm_infos(fw_hostname, fw_api_username, fw_api_password):

    logging.info("Get the CPUID and UUID from the VM")

    try:
        fw = firewall.Firewall(fw_hostname, fw_api_username, fw_api_password)
        
        resp = fw.op("show system info")

        for t in resp.iter('vm-uuid'):
            uuid = t.text

        for t in resp.iter('vm-cpuid'):
            cpuid = t.text

        logging.debug("VM CPUID: {}".format(cpuid))
        logging.debug("VM UUID: {}".format(uuid))

        return (cpuid, uuid)
    
    except:
        logging.debug("Error when reaching Firewall")
        return False

def switch_to_panorama(r, fw_hostname, fw_api_username, fw_api_password, serialnumField):

    logging.info("Switch the fake panorama to the real one")

    fw = firewall.Firewall(fw_hostname, fw_api_username, fw_api_password)

    try:

        for lic in r:
            logging.debug("Push license to the VM : {}".format(lic['featureField']))

            req = "<request><license><install>"
            req += lic['keyField']
            req += "</install></license></request>"

            fw.op(req, cmd_xml=False)
    
    except:
        logging.debug("Unable to push license to the PanOS Firewall")
        raise

    logging.info("Firewall will restart just after the license push. Wait him.")
    fw.syncreboot()

    logging.info("Refresh informations and test connectivity")
    fw.refresh_system_info()

def register_vm(cpuid, uuid):
    """Register the VM to the support portal within CPUID and UUID

    Args:
        cpuid: CPUID of the VM
        uuid: UUID of the VM 

    Returns:
        r: string in json format containing all the license

    """

    logging.info("Register the VM with CPUID and UUID to the support API portal")
    
    global authcode, url, api

    data = { 
        "cpuid": cpuid, 
        "uuid": uuid, 
        "authCode": authcode
    }

    headers = {'apikey': api, 'user-agent': 'PANW-Lic-API/0.1.0'}

    try:
        r = requests.post(url, headers=headers, json=data )
        r.raise_for_status()
    except requests.exceptions.HTTPError as e:
        logging.debug("Can't register the VM with the autcode {}.\n See the message {}".format(authcode, e.response._content))
        raise e
    except:
        logging.debug("Error when reaching API License Server")
        raise
    else:
        return r.text

def store_lic(r = None):
    """Extract Licenses and store it

    Args:
        r: Response from the API Support Portal 

    Returns:
        bolean: True if all license has been writen or False if something wrong append

    """

    logging.info("Extract Licenses and store it")

    if r == None:
        logging.debug("Nothing to process")
        return False

    for lic in r:

        try:
            fName = "./licenses/"+lic['serialnumField']+"/"
            if lic['featureField'] == ('AutoFocus Device License'):
                fName += "PAN-VM-autofocus.key"
            else:
                fName += lic['partidField']+".key"
            write_lic_file(fName)
        except:
            logging.debug('Problem to store lic in the filesystem')
            return False
    
    return True

    
def get_authcodes(r = None):
    """Extract VM auth code from the API support portal answer

    Args:
        r: Response from the API Support Portal 

    Returns:
        dict: authcodes or False if something wrong append

    """

    logging.debug("Process License File and store it")

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
    
def get_serialnumber(r = None):
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

def write_lic_file(filename):
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
    except:
        logging.debug("File directory doesn't exist or cannot be created")

    try:
        f = open(filename,"w")
        f.write(lic['keyField'])
        f.close()
    except:
        logging.debug("File cannot be created")
        raise


def register(fw_hostname = None):

    if fw_hostname == None:
        raise ValueError("Undefined hostname")
        return False

    logging.info("Registering for %s" % fw_hostname)


    global fw_api_username, fw_api_password
    
    (cpuid, uuid) = get_vm_infos(fw_hostname, fw_api_username, fw_api_password)
    
    r = register_vm(cpuid, uuid)

    r = json.loads(r)

    store_lic(r)

    serialnumField = get_serialnumber(r)

    switch_to_panorama(r, fw_hostname, fw_api_username, fw_api_password, serialnumField)

    logging.info("Done")
