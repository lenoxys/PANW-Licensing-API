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
import argparse
import logging
import json
import requests
import urllib

#sys.tracebacklimit = 0

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

    logging.debug("Get the CPUID and UUID from the VM")

    try:
        fw = firewall.Firewall(fw_hostname, fw_api_username, fw_api_password)
        
        resp = fw.op("show system info")

        for t in resp.iter('vm-uuid'):
            uuid = t.text

        for t in resp.iter('vm-cpuid'):
            cpuid = t.text

        print(uuid)
        print(cpuid)

        return (cpuid, uuid)
    
    except:
        print("Error when reaching Firewall")
        return False

def switch_to_panorama(r, fw_hostname, fw_api_username, fw_api_password, serialnumField):

    logging.debug("Switch the fake panorama to the real one")
    
    global pn_hostname, pn_api_username, pn_api_password

    fw = firewall.Firewall(fw_hostname, fw_api_username, fw_api_password)

    # Pushing New panorama settings
    conf = device.SystemSettings(panorama = pn_hostname)
    fw.add(conf)
    conf.create()
    fw.commit(sync=True)

    for lic in r:
        logging.debug("Push license to the VM : {}".format(lic['featureField']))

        req = "<request><license><install>"
        req += lic['keyField']
        req += "</install></license></request>"

        fw.op(req, cmd_xml=False)

    fw.syncreboot()
    fw.refresh_system_info()

    pano = panorama.Panorama(pn_hostname, pn_api_username, pn_api_password)
    pano.add(panorama.DeviceGroup("undefined")).create()
    pano.add(fw)
    pano.commit(sync=True)

def forceauthcode(fw, auth_codeField):

    logging.debug("Force Fetching licenses")

    for authcode in auth_codeField:
        logging.debug("Force auth code registration with : {}".format(authcode))
        req = "request license fetch auth-code {}".format(authcode)
        resp = fw.op(req)

def register_vm(cpuid, uuid):

    logging.debug("Register the VM with CPUID and UUID to the support API portal")
    
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
        return r.text

    except requests.exceptions.HTTPError as err:
        print ("Can't register the VM with the autcode {}.\n See the message {}".format(authcode, err.response._content))
        raise

    except:
        print("Error when reaching API License Server")
        raise

    return None

def store_lic(r = None):

    logging.debug("Process License File and store it")

    if r == None:
        print("Nothing to process")
        raise

    auth_codeField = []
    serialnumField = None

    try:

        for lic in r:
            
            fName = "./licenses/"+lic['serialnumField']+"/"

            if lic['featureField'] == ('AutoFocus Device License'):
                fName += "PAN-VM-autofocus.key"
            else:
                fName += lic['partidField']+".key"
            
            os.makedirs(os.path.dirname(fName), exist_ok=True)

            f = open(fName,"w")
            f.write(lic['keyField'])
            f.close()

            if lic['auth_codeField']:
                auth_codeField.append(lic['auth_codeField'])

            serialnumField = lic['serialnumField']

        return serialnumField, auth_codeField

    except:
        print ('Problem to store lic in the filesystem')
        raise


def register(fw_hostname = None):

    if fw_hostname == None:
        raise ValueError("Undefined hostname")
        return False

    print("Registering for %s" % fw_hostname)

    logging_format = '%(levelname)s:%(name)s:%(message)s'
    logging.basicConfig(format=logging_format, level=10)

    global fw_api_username, fw_api_password
    
    (cpuid, uuid) = get_vm_infos(fw_hostname, fw_api_username, fw_api_password)
    
    r = register_vm(cpuid, uuid)

    r = json.loads(r)

    (serialnumField, auth_codeField) = store_lic(r)

    switch_to_panorama(r, fw_hostname, fw_api_username, fw_api_password, serialnumField)

    logging.debug("Done")
