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

import urllib.request
import urllib.parse

try:
    from config import *
except ImportError:
    for arg in sys.argv: 1
# use the command line to call the function from a single script.
    print ("Run setup.py")
    sys.exit(0)

from pandevice import firewall
from pandevice import panorama
from var_dump import var_dump

url = 'https://api.paloaltonetworks.com/api/license/activate'

# Firewall Conf
fw_hostname = '10.0.3.100'
fw_api_username = 'admin'
fw_api_password = 'admin'

pn = None

def get_vm_infos(fw_hostname, fw_api_username, fw_api_password):
    try:
        fw = firewall.Firewall(fw_hostname, fw_api_username, fw_api_password)
        
        resp = fw.op("show system info")

        for t in resp.iter('vm-uuid'):
            uuid = t.text

        for t in resp.iter('vm-cpuid'):
            cpuid = t.text

        print("%s" % cpuid)
        print("%s" % uuid)

        return (uuid, cpuid)
    
    except:
        print("Error when reaching Firewall")
        return False

def register_vm(cpuid, uuid):
    global authcode, url, api

    data = urllib.parse.urlencode({ "cpuid" : cpuid , "uuid" : uuid ,"authCode" : authcode })
    data = data.encode('ascii')

    try:
        req = urllib.request.Request(url=url, data=data)
        req.add_header('apikey', api)
        r = urllib.request.urlopen(req)

    except:
        print("Error when reaching API License Server")
        var_dump(req)
        return False

    for x in r:
        resp = json.loads(x)

    for lic in resp:
        var_dump(lic)
        fName = "./licenses/"+lic['serialnumField']+"/"

        ## while statement added to address the issues with the fact the auto focus licences
        ## does not have a partidfield to work with
        ## so instead look at the feature Field and if autofocus
        ## manual set the file name.

        if lic['featureField'] == ('AutoFocus Device License'):
            fName += "PAN-VM-autofocus.key"
        else:
            fName += lic['partidField']+".key"
        
        os.makedirs(os.path.dirname(fName), exist_ok=True)

        f = open(fName,"w")
        f.write(lic['keyField'])
        f.close()

    r.close()

    return True

def register(fw_hostname):

    print("Registering for %s" % fw_hostname)

    # Get command line arguments
    parser = argparse.ArgumentParser(description="Third party license server API validation for VM without Internet access")
    parser.add_argument('-v', '--verbose', action='count', help="Verbose (-vv for extra verbose)")
    parser.add_argument('-q', '--quiet', action='store_true', help="No output")

    args = parser.parse_args()

    ### Set up logger
    # Logging Levels
    # WARNING is 30
    # INFO is 20
    # DEBUG is 10

    logging_format = '%(levelname)s:%(name)s:%(message)s'
    logging.basicConfig(format=logging_format, level=10)

    global fw_api_username, fw_api_password
    
    (cpuid, uuid) = get_vm_infos(fw_hostname, fw_api_username, fw_api_password)
    
    register_vm(cpuid, uuid)
