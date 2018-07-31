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

def main():

    f = open('config.py', 'w')

    print ("Licensing API Key")
    
    print ("The license API key provides users access to the various license functions through REST APIs . It authenticates the users that access the licensing APIs and one key can be used for all license API calls.")
    print ("Super User permissions are required to access the Enable link below to regenerate or disable the license key.")
    print ("You'll find this key under Palo Alto Networks Support Website : Assets > Licensing API Key")

    api = input("Licensing API Key: ")
    f.write("api = '%s'\n" % api) 

    api = input("Panorama IP or FQDN: ")
    f.write("pn_hostname = '%s'\n" % api) 

    api = input("Panorama API username: ")
    f.write("pn_api_username = '%s'\n" % api) 

    api = input("Panorama API password: ")
    f.write("pn_api_password = '%s'\n" % api) 

    api = input("Default Firewall admin username: ")
    f.write("fw_api_username = '%s'\n" % api) 

    api = input("Default Firewall admin password: ")
    f.write("fw_api_password = '%s'\n" % api) 

    f.close()

if __name__== "__main__":
    main()