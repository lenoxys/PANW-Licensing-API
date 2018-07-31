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
            uuid = urllib.parse.quote(t.text)

        for t in resp.iter('vm-cpuid'):
            cpuid = urllib.parse.quote(t.text)

        print(uuid)
        print(cpuid)

        return (uuid, cpuid)
        #return ("564D02C6-2B02-0AEA-B5E1-CFA650179F3C", "ESX:F2060300FFFBAB1F")
    
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

    logging.debug("Push license to the VM ")

    req = "<request>"+"<license>"

    for lic in r:
        req += "<install>"
        req += lic['keyField']
        req += "</install>"

    req += "</license>"+"</request>"

    resp = fw.op(req, cmd_xml=False)

    pano = panorama.Panorama(pn_hostname, pn_api_username, pn_api_password)
    pano.add(panorama.DeviceGroup("undefined")).create()
    pano.add(fw)
    pano.commit(sync=True)

    #fw.fetch_licenses_from_license_server()


def forceauthcode(auth_codeField):

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

    var_dump(r)

    r = json.loads(r)

    #r = {"lfidField":"29752118","partidField":"PAN-VM-50-TP","featureField":"Threat Prevention","feature_descField":"Threat Prevention","keyField":"kV2PtJ89nn6yv/cZyvct3H7AvQQTpv6oQmLYM/be0PN/ycRme+kmy3TlsleSoVuX\nKbvBvPICLXM1JuT1cy4S+abL28/sktqedT92GVJN0/yp5uqoXmRrE4XOXrGS6uva\n/zxta9JXz/55EZrl8mZcSnBUyAd/ttktp7fJhurG6CTyCTAo/COXyMyBcbkjjO3w\ntZsYPLU2puudCP6bQ9KHX8F4AfZj1hQniDmjApc8ZRnfHqyw42yf4ALjkHwpNyZ/\n9kFWpa5mj8XoyS7zsQFXGxaPJbes35JRXCG6jfskh8emWZrmLu1Iag/48ilx5A7z\n9MCs8YzbdZNtM/ku+SKiUQ==\n","auth_codeField":"","errmsgField":"null","typeField":"SUB","regDateField":"2018-07-31T00:27:33","startDateField":"7/31/2018","vm_capacityField":"null","uuidField":"null","cpuidField":"null","mac_baseField":"null","mac_countField":"null","drrField":"null","serialnumField":"015351000014516","expirationField":"7/31/2019 12:00:00 AM","PropertyChanged":"null"},{"lfidField":"29752121","partidField":"PAN-VM-50-URL2","featureField":"BrightCloud URL Filtering","feature_descField":"BrightCloud URL Filtering","keyField":"i7/tlcx9yvpGWlAJiSfh3WLuoMKgftD4njeLRyyKf/5ReDL4Y2lg1blTpP2lYPha\nJ8c1bsOfOzAYhvke5sx1i1h2KJw7y52Oryl06CCZtA/SMeBf0d5Z+cIGNGy9f3gd\n4pd8udB26OW6Y6AEnVI2IRT+dympO3hyueqjSxJ14BxkIzXz9RvDqlEncl7DOdiQ\nDGpmQSda3IQewNnU1syFQigOTkbgEQaKmtA8sN3g4NuNcPWhjcXPsrUDQwdydQLB\nFZsCUB//2Zqn/9SBqxZR5Y7U1hofM/L6xT5hdk57BSx0g4izqaEIdQ8ULegK7WQl\nKQSaLfHgM8e8XDLcnb6nEw==\n","auth_codeField":"","errmsgField":"null","typeField":"SUB","regDateField":"2018-07-31T00:27:33","startDateField":"7/31/2018","vm_capacityField":"null","uuidField":"null","cpuidField":"null","mac_baseField":"null","mac_countField":"null","drrField":"null","serialnumField":"015351000014516","expirationField":"7/31/2019 12:00:00 AM","PropertyChanged":"null"},{"lfidField":"29752124","partidField":"PAN-VM-50-GP","featureField":"GlobalProtect Gateway","feature_descField":"GlobalProtect Gateway License","keyField":"uTcgMAqIXmtPeC8bPEYN3cRqmdGNAaVtcZ5iUwoh0ce9l5A2M6ZLMBTwS4V64pr9\n28tbmRG3Ls82fbJiDnlzrxHh+WjmaYFzbGkImHwNLgoKzqKLKGxlg5U9Gu5rzOAl\nN5si9ncBpvWkS7THdgVu81xNC6f+44DDwictj3gxcIFgS1TO2qbsyJ+C9AYTgbl5\nNUgQaEaghQuwua8malX6cqVApnZndI2WPAAftycaz47LN8cG4hMZuAukbFBILCib\nR7EVAEzriHGH1ZD6X63V412sP7GuK8EqYeoOLPtdEFDOSa5mo9hoouXIJwRuQmKf\nawi0pdmUET4BfgbwcpcDmA==\n","auth_codeField":"","errmsgField":"null","typeField":"SUB","regDateField":"2018-07-31T00:27:33","startDateField":"7/31/2018","vm_capacityField":"null","uuidField":"null","cpuidField":"null","mac_baseField":"null","mac_countField":"null","drrField":"null","serialnumField":"015351000014516","expirationField":"7/31/2019 12:00:00 AM","PropertyChanged":"null"},{"lfidField":"29752127","partidField":"PAN-VM-50-WF","featureField":"WildFire License","feature_descField":"WildFire signature feed, integrated WildFire logs, WildFire API","keyField":"ZHCO3duAzgJNofz8zJXD1NrztnKi+f4sOwNuyrMR5eUQhKffQrWe3f/E94LYeCg6\nXNWrNS5PBAmUcpZaJQVBI4AyGWhByipicd1VOWPsn7kOBTu50Gp/h2mOkshO6dYC\nJs3U1Mg8razUQUghhHr3R+fHK/XuQdu7P65qCTk39ev4BD9KmjgujENbQ+xR1iCK\nObrIhDE1jnnTrJuLuJXIJb8y7EvTtoB3C0n7zJIPTFHW7uy1/2kfysTz6FT5+H6L\nJZdinWj/sUnFIfhrr1CzLghGxFTwzDdTV43QOMfZLM6MM7yo8ketU7EJaCGCg/GZ\nvXl02T+g1A6ROmnzbafiNw==\n","auth_codeField":"","errmsgField":"null","typeField":"SUB","regDateField":"2018-07-31T00:27:35","startDateField":"7/31/2018","vm_capacityField":"null","uuidField":"null","cpuidField":"null","mac_baseField":"null","mac_countField":"null","drrField":"null","serialnumField":"015351000014516","expirationField":"7/31/2019 12:00:00 AM","PropertyChanged":"null"},{"lfidField":"29752130","partidField":"PAN-VM-50-URL4","featureField":"PAN-DB URL Filtering","feature_descField":"Palo Alto Networks URL Filtering License","keyField":"sg3SQqBs+2IqKzsB6X98gwzHf66GkwCk0JlPQLvgQbgvlbA56kKvZQs7ugb9LTLa\n6U7epUk7jCtCz4mRyNPUl3NnIWxrZAA8+t/FYRAPe+y8ZdAdWTlMv+1xUU7UUdMr\nBWA5+0fXnU2L4mMMPtgIrIVe4PGt3m6OXLWIvXP54ABZ+mv8CQSYjPtJBCSLYPnX\nEEY2FqFuNBUYl/hD5bqLFW90GIW3855nAa6Z7PJJ6WzFb0ZvHIg1frayWkpVTIKG\nAsGEeECoouImoBccIJlRI6MxHPlGKvDeRWeuFIPY/yO2hfZy+zeR38X5s7YdD+yJ\nRo41GMgFHFOkRf3Uscihug==\n","auth_codeField":"","errmsgField":"null","typeField":"SUB","regDateField":"2018-07-31T00:27:36","startDateField":"7/31/2018","vm_capacityField":"null","uuidField":"null","cpuidField":"null","mac_baseField":"null","mac_countField":"null","drrField":"null","serialnumField":"015351000014516","expirationField":"7/31/2019 12:00:00 AM","PropertyChanged":"null"},{"lfidField":"29752133","partidField":"PAN-SVC-PREM-VM-50-3YR","featureField":"Premium","feature_descField":"24 x 7 phone support; advanced replacement hardware service","keyField":"Pyo1FIVH6Ts6oUr95el+P5vdYEzID9Q4Rpf4PA7xyjFUZZkyhX4z/36uzgpQIrBN\n3AJo9rTCNg1+wDUqTmktooHWQflFD0H4Y6o/uh+wPbCMQFv9DiNKDrbINC32xYaL\nVlLWmLOIin6/hOFOHL2hs956lyPuSIkYvH2dM40tV5ho+pWIymO1Krr5jWEmSCTa\niULM0YFdelTOkzVOTfafl43HHboK6c9N/IKpjV3UY7V3yULxe0pjMrzd4+tQNUS1\nx1inM8s1Q//SVgfkiL4QQwwAnO9QRV5xVM4gamsP/LnbdIcgVMdvPdsD9+qzzpNB\n3KqUc7Dxh+5GFbq7wudlIA==\n","auth_codeField":"","errmsgField":"null","typeField":"SUP","regDateField":"2018-07-31T00:27:36","startDateField":"7/31/2018","vm_capacityField":"null","uuidField":"null","cpuidField":"null","mac_baseField":"null","mac_countField":"null","drrField":"null","serialnumField":"015351000014516","expirationField":"7/31/2019 12:00:00 AM","PropertyChanged":"null"},{"lfidField":"29752136","partidField":"PAN-GP-VM-50-PORTAL","featureField":"GlobalProtect Portal","feature_descField":"GlobalProtect Portal License","keyField":"L9QXw+f75Lu39rDdGKDEDButoxWhei3CyCgimktr1ADG8Kupjczo9d3q9BzVi8+V\nWsGjNfYYUz2BpMXY8Lfr/p7SQ3b7t1OcWDIWg7LfcukXdLlpUplzwDi+AExgL2fR\nGuygazDKHUNJUkdqFXVkvJxDLUfbWXjXZSnzpqYo2KD3MmYRsYymqrAdxwEbYs0h\n9QW9DDJXr2kc8e4RvE0hMTzsF7xILezvHF9zMUGhrs9eCokJa9UXIWvrko7Poj2T\nP6nCdRWbFqLX9N1tkZ46taw7HwWUAQ0NCSUquBdTCX/KTB+yPX12IpBEhmz2Ye3o\nfHTjMUWP5dBxup4iL5n3nQ==\n","auth_codeField":"","errmsgField":"null","typeField":"SUB","regDateField":"2018-07-31T00:27:36","startDateField":"7/31/2018","vm_capacityField":"null","uuidField":"null","cpuidField":"null","mac_baseField":"null","mac_countField":"null","drrField":"null","serialnumField":"015351000014516","expirationField":"","PropertyChanged":"null"},{"lfidField":"29752139","partidField":"PAN-VM-50-SE","featureField":"PA-VM","feature_descField":"Standard VM-50 Eval","keyField":"Mnv5t7C7hBnk6imhNZzTKGTon7HM+zE6NGWLZBy3NhdGNxwb2nU9yvSAsh7dHDRg\nx3kWMsxhPcY3f3++xszxQQfxT12cpvJa9lax1jPKw0oynllj5jGA51z/PcDg5nWO\neivSmQLeweuTKeUlMHN39TgNseoR9JytCmzLzssx4ST5VThMwZg8MzmmOqxG02l6\nzkeqOBqI6c4g/zCbAROhYWyd/gxG4F3RD/T7KqFyETp8psbWdpGaGIQuK/UEYs+x\nRxpDz1I511hSycmkLmQFOtLD9DzsrfkT8pF0zIWZ0qrfasZKD3SwSoTBrEPbIisG\ndJrL36OVbB4BwOXKyDTLKQ==\n","auth_codeField":"V5001326","errmsgField":"null","typeField":"SUB","regDateField":"2018-07-31T00:27:36","startDateField":"7/31/2018","vm_capacityField":"null","uuidField":"null","cpuidField":"null","mac_baseField":"null","mac_countField":"null","drrField":"null","serialnumField":"015351000014516","expirationField":"10/29/2018 12:00:00 AM","PropertyChanged":"null"},{"lfidField":"null","partidField":"null","featureField":"AutoFocus Device License","feature_descField":"AutoFocus Device License","keyField":"sW5ARqffMJJ8yz90EfsxCVVwYwebxVfIMfNGErxeYlPH5Frf7iYMywXsmrgv/ibt\notaPOqp5dw4PZKqs3mce2WCjMKDznV3fbvzn9vYSVTBVDrArpBPupMLYFZIlr5Z5\nAPlaQGrqXcZoK7wFuQ832Eu7H7qG1SVTdmo7otD0fgniHSFVLSv1FfQ2yr8xDOA/\nFdiB4mF9x+aX/OkkB/ZaQMAGsXRwWJx3fD/uH0Tm1pdZ/IMmtFfJz2hKevbUqLSw\nQHg7jIznTRFpBOq2l2CcPm4BGGpGw/eIZok9zuc1jElw2J+sHZ5NmiHQm737mF+j\n+Bi4/A6RxQMdiMJS4i4bFQ==\n","auth_codeField":"S7763958","errmsgField":"null","typeField":"RENSUB","regDateField":"2018-07-31T00:27:38.6544987-07:00","startDateField":"5/29/2032","vm_capacityField":"null","uuidField":"564DB238-B142-FC82-B10E-396A22B09D3E","cpuidField":"ESX:F2060300FFFBAB1F","mac_baseField":"E4:A7:49:71:05:00","mac_countField":"256","drrField":"N","serialnumField":"015351000014516","expirationField":"5/29/2032 12:00:00 AM","PropertyChanged":"null"}

    (serialnumField, auth_codeField) = store_lic(r)

    switch_to_panorama(r, fw_hostname, fw_api_username, fw_api_password, serialnumField)

    forceauthcode(auth_codeField)

    logging.debug("Done")

# if __name__ == '__main__':
#     register("10.0.3.102")