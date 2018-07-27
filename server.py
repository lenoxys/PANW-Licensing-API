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

def main():

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
    if args.verbose is None:
        args.verbose = 0
    if not args.quiet:
        logging_level = 20 - (args.verbose * 10)
        if logging_level <= logging.DEBUG:
            logging_format = '%(levelname)s:%(name)s:%(message)s'
        else:
            logging_format = '%(message)s'
        logging.basicConfig(format=logging_format, level=logging_level)

    print ("Connecting!")
    global pn, pn_hostname, pn_api_username, pn_api_password
    #pn = panorama.Panorama(pn_hostname, pn_api_username, pn_api_password)
    #pprint (pn.op("show devices all"))

    global fw, fw_hostname, fw_api_username, fw_api_password
    fw = firewall.Firewall(fw_hostname, fw_api_username, fw_api_password)
    print('Firewall system info: {0}'.format(fw.refresh_system_info()))
    resp = fw.op("show system info")

    for t in resp.iter('vm-uuid'):
        uuid = t.text

    for t in resp.iter('vm-cpuid'):
        cpuid = t.text
    
    print ("cpuid: %s" % cpuid)    
    print ("uuid: %s" % uuid)

    register_vm(cpuid, uuid)

def register_vm(cpuid, uuid):
    global authcode, url, api

    data =  urllib.parse.urlencode({ "cpuid" : cpuid , "uuid" : uuid ,"authCode" : authcode })
    data = data.encode('ascii')

    req = urllib.request.Request(url=url, data=data)
    req.add_header( 'apikey', api )

    var_dump (req)

    r = urllib.request.urlopen(req)

    dname = "plop"

    var_dump (r)

    for x in r:
        resp = json.loads(x)
        c = (len(resp))

    i=0
    ## while statement added to address the issues with the fact the auto focus licences
    ## does not have a partidfield to work with
    ## so instead look at the feature Field and if autoforcus
    ## manual set the file name.
    while i < c:
        if resp[i]['featureField'] == ('AutoFocus Device License'):
            fName = dname+"-PAN-VM-autofocus.key"
            file = open(fName,"w") 
            file.write(resp[i]['keyField'])
            file.close() 
            i+=1
        else:
            fName = dname+"-"+resp[i]['partidField']+".key"
            file = open(fName,"w") 
            file.write(resp[i]['keyField'])
            file.close() 
            i+=1
        
    r.close()

if __name__== "__main__":
    main()