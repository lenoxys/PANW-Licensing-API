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
import argparse
import socket
import threading
import register
import logging
import threading

from var_dump import var_dump

bind_ip = '127.0.0.1'

try:
    from config import *
except ImportError:
    for arg in sys.argv: 1
# use the command line to call the function from a single script.
    print ("Run setup.py")
    sys.exit(0)

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--debug", help="increase output debug", action="store_true")
parser.add_argument("-w","--wildcard_binding", help="Listen on all IP address", action="store_true")
args = parser.parse_args()

if args.debug:
    logging_format = '%(asctime)-15s:%(levelname)s:%(name)s:%(message)s'
    logging.basicConfig(format=logging_format, level=10)
else:
    sys.tracebacklimit = 0
    logging_format = '%(message)s'
    logging.basicConfig(format=logging_format, level=20)

if args.wildcard_binding:
    bind_ip = '0.0.0.0'

# Default Panorama port
bind_port = 3978

def clientthread(conn, address):
    logging.debug('Accepted connection from {}:{}'.format(address[0], address[1]))
    try: 
        register.Register(address[0])
    except:
        logging.debug('Something wrong append from {}:{}'.format(address[0], address[1]))
    finally:
        logging.debug('Closing connection from {}:{}'.format(address[0], address[1]))
        conn.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    global bind_ip, bind_port

    try:
        server.bind((bind_ip, bind_port))
    except socket.error as msg:
        logging.debug('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()

    server.listen(5)  # max backlog of connections

    logging.info('Listening on {}:{}'.format(bind_ip, bind_port))

    list_ip = list()

    while True:

        try:
            client, address = server.accept()

            if address[0] in list_ip:
                client.close()
                logging.debug("Already processed")
                raise

            list_ip.append(address[0])
    
            client.settimeout(60)
            threading.Thread(target = clientthread, args = (client,address)).start()

        except socket.error as exc:
            logging.info('Caught exception socket.error : {}'.format(exc))

        except KeyboardInterrupt:
            logging.debug("Keyboard Interrupt Exiting....")
            sys.exit()

        except:
            logging.debug("Something Wrong Append")

if __name__ == '__main__':
    main()