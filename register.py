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

    for lic in r:
        logging.debug("Push license to the VM : {}".format(lic['featureField']))

        req = "<request><license><install>"
        req += lic['keyField']
        req += "</install></license></request>"

        if lic['featureField'] == "PA-VM":
            #fw.op("<request><restart><system></system></restart></request>", cmd_xml=False)
            #fw.syncreboot()
        else:
            fw.op(req, cmd_xml=False)

    pano = panorama.Panorama(pn_hostname, pn_api_username, pn_api_password)
    pano.add(panorama.DeviceGroup("undefined")).create()
    pano.add(fw)
    pano.commit(sync=True)

    fw.fetch_licenses_from_license_server()

    #forceauthcode(fw, auth_codeField)


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
    
    #r = register_vm(cpuid, uuid)

    #var_dump(r)

    #r = json.loads(r)

    r = {"lfidField":"29762300","partidField":"PAN-VM-50-TP","featureField":"Threat Prevention","feature_descField":"Threat Prevention","keyField":"JCVPqI+KOpECAQWxXzt5p41M4HKmxS2eQ7OZJrXkO+DCTXjOwGy/j3/Lw8qDZ6B5\nx+K+bJwgCxS5tVcF8USLSzLiDkMym6eoOEaROX3ehceC/MDnfEz5MM/N7ll9s3EU\n2FVggMk3o3hVgpp1W5eUjIZYKvKCFtiLR4vVPnKvETuOBv/3uK0J5bLdU3c3B3up\nZjfnxfa/iKJ3SJntuAtqpVwVanI+Z4IoLiR74+cjI5c/n8HERbUkRfYejz0ZckE7\n5RsTY9NyTNzqtTlOdfC7Ot2P3ry/XLSaN/gpB0QE3mg8RrzlJeLwuw3pLYJSIIQA\n3dt7ZiYCC37gvo8jr04K+Q==\n","auth_codeField":"","errmsgField":"null","typeField":"SUB","regDateField":"2018-07-31T09:14:34","startDateField":"7/31/2018","vm_capacityField":"null","uuidField":"null","cpuidField":"null","mac_baseField":"null","mac_countField":"null","drrField":"null","serialnumField":"015300000014531","expirationField":"7/31/2019 12:00:00 AM","PropertyChanged":"null"},{"lfidField":"29762303","partidField":"PAN-VM-50-URL2","featureField":"BrightCloud URL Filtering","feature_descField":"BrightCloud URL Filtering","keyField":"A0UH0xclE6roEBcShHfjKOzKDsnT43mXnpmf/nx8aRsSd579lpPaW9KVaPtct7Jg\nS+3WUtFWH+Nl4rhQ6t4vw0HASxSV2AqmSA2UW4lXb3+S71tAWnoEUYwPQLORgL5+\ns2ooD5atRmFP5W4AJDOHqKJXmeLJgrcs4Y/faTz9uqmreT52Uz5N6rlr1OeQYS/d\nqhJbcsEUENpk99GTm+94fo0IjtLdn6iOg1XXHlk9XIgdvDH/wHLuRcF4o4ze2vfm\n1pcK9P/D+ng5Zme0XnPADq77wCr/uRisnYDrxzO/7/XVKqpchasurk3Dl6St13W7\nE/8IRqo4Gev/szDCJcdW0g==\n","auth_codeField":"","errmsgField":"null","typeField":"SUB","regDateField":"2018-07-31T09:14:34","startDateField":"7/31/2018","vm_capacityField":"null","uuidField":"null","cpuidField":"null","mac_baseField":"null","mac_countField":"null","drrField":"null","serialnumField":"015300000014531","expirationField":"7/31/2019 12:00:00 AM","PropertyChanged":"null"},{"lfidField":"29762306","partidField":"PAN-VM-50-GP","featureField":"GlobalProtect Gateway","feature_descField":"GlobalProtect Gateway License","keyField":"KYeTM4nHO2DmZoVVSgszJBuCB+2SLmidFpbObeDjJwN6vdbyV0eRvuchq0j3qfxu\nH6IqWS69FPAFJJwI0d04kbzVUD+M7Kkx2yjqSgROkKpTJqAFl7JF6do1coZwqc0n\n9CFHoIVsPcQjyzUUf+eQuUIbDEQTgXaGP+850p3QyRb0wmOwnTgtlhDK/7W65z42\nNdLiRb3e9VQEFam5S6bQaitwBefTDgRDuOYCuHMhln6idz90CRsSRGk2clm2Dqnc\nDu/jQtNSutGpuBN218mdLKtudDkDtjKsFywm5KjrWe4WzfHqIsoMXPjt0BqPOjCu\nA1jHqv/K/b7KVERUykxErA==\n","auth_codeField":"","errmsgField":"null","typeField":"SUB","regDateField":"2018-07-31T09:14:34","startDateField":"7/31/2018","vm_capacityField":"null","uuidField":"null","cpuidField":"null","mac_baseField":"null","mac_countField":"null","drrField":"null","serialnumField":"015300000014531","expirationField":"7/31/2019 12:00:00 AM","PropertyChanged":"null"},{"lfidField":"29762309","partidField":"PAN-VM-50-WF","featureField":"WildFire License","feature_descField":"WildFire signature feed, integrated WildFire logs, WildFire API","keyField":"V2siPYjCj8HmIP5FMsS4+lQjZ56/gXCwQ3EgLCGCQedX1BWB6/PwXbO3y72EvRUP\nKxTKVl9OJxy4SeuMJGSFSSS529sfJY2nLhBNfcoC7ua9/SR+sswjzikIDZ+CxMny\nY2mqrzxuM+9e52CULLLwwJ5yG6++4afcKsDqcivc7pxx5Ng4E+FkW8SEjh3XVcf+\n9lVll8Np1VOE7sbmqW5wIrS3uzv+hDv85EabgYPmIk7Y3OOR8MzQVV9TqPm6Nqqx\nDMCya3TQeOxMyrIrMNyXhsDI0vNB/eF07QMWS54t/0yJcx1UtMySjNX4h9BRwSDr\n/BOtc5KAK6ougM0fL9e+uw==\n","auth_codeField":"","errmsgField":"null","typeField":"SUB","regDateField":"2018-07-31T09:14:37","startDateField":"7/31/2018","vm_capacityField":"null","uuidField":"null","cpuidField":"null","mac_baseField":"null","mac_countField":"null","drrField":"null","serialnumField":"015300000014531","expirationField":"7/31/2019 12:00:00 AM","PropertyChanged":"null"},{"lfidField":"29762312","partidField":"PAN-VM-50-URL4","featureField":"PAN-DB URL Filtering","feature_descField":"Palo Alto Networks URL Filtering License","keyField":"FnbHyY2uHXnGTKTH4/pHXKHrThdKdKFja/hRdIKqnROi3KziTLHrj6RcrAPeAtIj\nZ2i3oA8KB+BZf3OcADFME5almhMKZZUb3kLxYIvXVkK+LeG1D9dXAOMLC+gowkkX\ndS5S2N42Yuhp1dGGoSp8VaHAo+Nn0+pBvrgOe6+Smz9on/eN0A5d5CacH+dUu+Ev\nwWkzC4H6bP2QALbUz2kMuwY8fntmUf5dByehOJcbC7HtXvLL0DIGt8y3/Cv/WTNq\nrhxNEumoVMxRVsMd0l7zi6EQ0u1WeZ9bQvb1FBclstHhLoGqk9AB385OZr3AcjXq\n9wa6m6TcVbQcpIP3WDSlRA==\n","auth_codeField":"","errmsgField":"null","typeField":"SUB","regDateField":"2018-07-31T09:14:37","startDateField":"7/31/2018","vm_capacityField":"null","uuidField":"null","cpuidField":"null","mac_baseField":"null","mac_countField":"null","drrField":"null","serialnumField":"015300000014531","expirationField":"7/31/2019 12:00:00 AM","PropertyChanged":"null"},{"lfidField":"29762315","partidField":"PAN-SVC-PREM-VM-50-3YR","featureField":"Premium","feature_descField":"24 x 7 phone support; advanced replacement hardware service","keyField":"EPkWiYlS81EjDQIfBx0aTvGBTq66cJ1ZCZxsM7tKHv9R0SPkuYDPJbNQ8AfKC3iy\nUW2qg1j/5OgcjcT7h2WPdaPqC7KsktA+plq75jU7HxUUDBAIrsJVsZfHBeY/Z0Xj\nSdlIA1Js+/cmK1zxmrfWV38YHI6RYtN2JlWLYjrwwPQ8WlbL2QuTxYz9SM8slpru\nAcxLUwBno0j+YRo//fK0vfS9ZEEihxH4VR5Odd/8AFWYjggWxL47m6HmqX1BVuKy\nqpbWh/iZ3zLa2qsuyuwZvH06CbeeUcNyEGPmW8y3vaEMk7rBrJ78G7Qjt6otBBDd\n+XBD9GJVptWANfWYiDoNeA==\n","auth_codeField":"","errmsgField":"null","typeField":"SUP","regDateField":"2018-07-31T09:14:37","startDateField":"7/31/2018","vm_capacityField":"null","uuidField":"null","cpuidField":"null","mac_baseField":"null","mac_countField":"null","drrField":"null","serialnumField":"015300000014531","expirationField":"7/31/2019 12:00:00 AM","PropertyChanged":"null"},{"lfidField":"29762318","partidField":"PAN-GP-VM-50-PORTAL","featureField":"GlobalProtect Portal","feature_descField":"GlobalProtect Portal License","keyField":"DuKLvfsti5iCVETE+sRClw6OVBK+8JEuBNQkB9Da/7llLK0IrD37XA8XFBRCwH77\nxhc83T31yoRX7aWqSLX9/vWaEU0BDeeb86PryEOPSjyIravn1D8YrmuskR+M5YQj\ndnS0ZMceD9kHxFL0341Pz9V7UF4et809xhO2w6BXv1yy2+ck9XFlPlwmsVw4mfTJ\nEyE9kSaO927PU5nKGmgN16klIGseOKECn+hjtZIOGnzGQKEdarSdrNQ8JgUPA/Q0\nD8cXSks5FIK74IkqsADui7REPjNzQJROW1pYxz6JItrnMdpcaggPYgFa2EGCR2AG\nqfcJ4lz5bUidfzAWL9/SIw==\n","auth_codeField":"","errmsgField":"null","typeField":"SUB","regDateField":"2018-07-31T09:14:37","startDateField":"7/31/2018","vm_capacityField":"null","uuidField":"null","cpuidField":"null","mac_baseField":"null","mac_countField":"null","drrField":"null","serialnumField":"015300000014531","expirationField":"","PropertyChanged":"null"},{"lfidField":"29762321","partidField":"PAN-VM-50-SE","featureField":"PA-VM","feature_descField":"Standard VM-50 Eval","keyField":"SHoz3rnNppuvkKGAhLjEVUb/riiUw9ojt0p6A26zqx+szvDrivU3ub6GzCToCSGN\nQ5OG0eIj7CZcdGVgPhLmnaedT4BoBQLi4TqHUmizZm1rWWb/cmOotfO3EB3+t7Rs\n5bw1nJ5TGnQVobTM2WuZfMYzPufwgWIYdPP6m3QWrAGfjFN7o2TSGXgpQ1RqPV8Q\nuyObAMqskt6pQsHl71rhGWznv6OJdKEc0ARrTm3k2qe3IZXypE7BpwkW9P1JTlrT\nNWk8zdW7s1Tp1UoZ/ZJNAVdfQ4seE8XOd1Ih0RtxF98EbHEk7A8A4jYkY+3PBm6z\n61pVqab1FHyl/Z9W/8AXsw==\n","auth_codeField":"V1866272","errmsgField":"null","typeField":"SUB","regDateField":"2018-07-31T09:14:37","startDateField":"7/31/2018","vm_capacityField":"null","uuidField":"null","cpuidField":"null","mac_baseField":"null","mac_countField":"null","drrField":"null","serialnumField":"015300000014531","expirationField":"10/29/2018 12:00:00 AM","PropertyChanged":"null"},{"lfidField":"null","partidField":"null","featureField":"AutoFocus Device License","feature_descField":"AutoFocus Device License","keyField":"pmER9uh6VN8bmIGyby/Tp/ez/S4qXs2/Or4kEPHKiYQj09fNkvVZodKUnZVRlQdH\nQteGac/aBkLEOEyHsyWdHp5HLnfKkEhK/5zzP15RlNcFnb/Gn5N6p7BZzs14jXKA\nh3kBxrHfXlh6EfmLWuatUfyHnP8GjAx0mWo1Pyj3y2MiG4/7/AhYf94Sfuf7BPRi\nHgeciM3HM7TyieDb3bqrap20AyFOW8Ys39ASqyAt4TqfiIPROUsNrE8ESpUkh7xb\n33jyuVdIcdtBUpemsTMiQiCgrJV28WeJS7o6aYC+MvW/SX/igPPVZ73kaPr8c90l\nNrPvQnaU3hhmUpbKF5aQ1Q==\n","auth_codeField":"S3373007","errmsgField":"null","typeField":"RENSUB","regDateField":"2018-07-31T09:14:40.1164968-07:00","startDateField":"5/29/2032","vm_capacityField":"null","uuidField":"ESX%3AF2060300FFFBAB1F","cpuidField":"564DFBB0-C61E-7F9A-4AFB-9491AFF6AAF2","mac_baseField":"E4:A7:49:71:05:00","mac_countField":"256","drrField":"N","serialnumField":"015300000014531","expirationField":"5/29/2032 12:00:00 AM","PropertyChanged":"null"}

    (serialnumField, auth_codeField) = store_lic(r)

    switch_to_panorama(r, fw_hostname, fw_api_username, fw_api_password, serialnumField)

    logging.debug("Done")

# if __name__ == '__main__':
#     register("10.0.3.102")