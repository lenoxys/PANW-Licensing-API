#!/usr/bin/env python

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

from pandevice import firewall
from pandevice import panorama
from var_dump import var_dump

# Panorama Conf
pn_hostname = '10.0.0.2'
pn_api_username = 'admin'
pn_api_password = 'admin'

# Firewall Conf
fw_hostname = '10.0.3.100'
fw_api_username = 'admin'
fw_api_password = 'admin'

pn = None

def main():

    # Get command line arguments
    parser = argparse.ArgumentParser(description="Upgrade a Palo Alto Networks Firewall or Panorama to the specified version")
    parser.add_argument('-v', '--verbose', action='count', help="Verbose (-vv for extra verbose)")
    parser.add_argument('-q', '--quiet', action='store_true', help="No output")
    parser.add_argument('-n', '--dryrun', action='store_true', help="Print what would happen, but don't perform upgrades")

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

    print "Connecting!"
    global pn, pn_hostname, pn_api_username, pn_api_password
    #pn = panorama.Panorama(pn_hostname, pn_api_username, pn_api_password)
    #pprint (pn.op("show devices all"))

    global fw, fw_hostname, fw_api_username, fw_api_password
    fw = firewall.Firewall(fw_hostname, fw_api_username, fw_api_password)
    print('Firewall system info: {0}'.format(fw.refresh_system_info()))
    resp = fw.op("show system info")

    for t in resp.iter('vm-uuid'):
        print t.text

    for t in resp.iter('vm-cpuid'):
        print t.text

if __name__== "__main__":
    main()