#!/usr/bin/python3

from __future__ import print_function, unicode_literals

import os
import os.path
import sys

from Requester import Requester

try:
    from urllib2 import build_opener, HTTPCookieProcessor, Request, HTTPSHandler
    from urllib import urlencode
    from httplib import IncompleteRead
except ImportError:
    from urllib.request import build_opener, HTTPCookieProcessor, Request, HTTPSHandler
    from urllib.parse import urlencode
    from http.client import IncompleteRead
try:
    from cookielib import LWPCookieJar
except ImportError:
    from http.cookiejar import LWPCookieJar
from getpass import getpass
from argparse import ArgumentParser
from netrc import netrc, NetrcParseError
from snxvpnversion import VERSION


def parse_config_file(home):
    cfg = {}

    cfgf = None
    if home:
        try:
            cfgf = open(os.path.join(home, '.snxvpnrc'), 'rb')
        except (OSError, IOError):
            pass
    bool_opts = ['debug', 'save_cookies']
    if cfgf:
        for line in cfgf:
            line = line.strip().decode('utf-8')
            if len(line) == 0 or line.startswith('#'):
                continue
            k, v = line.split(None, 1)
            if k == 'server':
                k = 'host'
            k = k.replace('-', '_')
            if k in bool_opts:
                v = (v.lower() in ('true', 'yes'))
            cfg[k] = v

    return cfg


def parse_args(cfg, home):
    host = cfg.get('host', '')
    cookiefile = cfg.get('cookiefile', '%s/.snxcookies' % home)
    cmd = ArgumentParser()
    cmd.add_argument \
        ('-c', '--cookiefile'
         , help='Specify cookiefile to save and attempt reconnect'
                ' default="%(default)s"'
         , default=cookiefile
         )
    cmd.add_argument \
        ('-D', '--debug'
         , help='Debug handshake'
         , action='store_true'
         , default=cfg.get('debug', None)
         )
    cmd.add_argument \
        ('-F', '--file'
         , help='File part of URL default="%(default)s"'
         , default=cfg.get('file', 'sslvpn/Login/Login')
         )
    cmd.add_argument \
        ('-E', '--extender'
         , help='File part of URL default="%(default)s"'
         , default=cfg.get('extender', 'sslvpn/SNX/extender')
         )
    cmd.add_argument \
        ('-H', '--host'
         , help='Host part of URL default="%(default)s"'
         , default=cfg.get('host', '')
         , required=not cfg.get('host', '')
         )
    cmd.add_argument \
        ('--ssl-noverify'
         , help='Skip SSL verification default="%(default)s"'
         , default=cfg.get('ssl_noverify', 'false')
         , required=False
         )
    cmd.add_argument \
        ('--height-data'
         , help='Height data in form, default "%(default)s"'
         , default=cfg.get('height_data', '')
         )
    cmd.add_argument \
        ('-L', '--login-type'
         , help='Login type, default="%(default)s"'
         , default=cfg.get('login_type', 'Standard')
         )
    cmd.add_argument \
        ('-P', '--password'
         , help='Login password, not a good idea to specify on commandline'
         , default=cfg.get('password', None)
         )
    cmd.add_argument \
        ('-p', '--protocol'
         , help='http or https, should *always* be https except for tests'
         , default=cfg.get('protocol', 'https')
         )
    cmd.add_argument \
        ('-R', '--realm'
         , help='Selected realm, default="%(default)s"'
         , default=cfg.get('realm', 'ssl_vpn_OTP')
         )
    cmd.add_argument \
        ('-s', '--save-cookies'
         , help='Save cookies to %(cookiefile)s, might be a security risk,'
                ' default is off' % locals()
         , action='store_true'
         , default=cfg.get('save_cookies', False)
         )
    cmd.add_argument \
        ('-S', '--snxpath'
         , help='snx binary to call, default="%(default)s", you might'
                ' want a full path here'
         , default=cfg.get('snxpath', 'snx')
         )
    cmd.add_argument \
        ('-u', '--useragent'
         , help='User-Agent to be passed to Checkpoint Portal, default="%(default)s"'
         , default=cfg.get('useragent', 'Mozilla/5.0 (X11; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0')
         )
    cmd.add_argument \
        ('-U', '--username'
         , help='Login username, default="%(default)s"'
         , default=cfg.get('username', '')
         )
    cmd.add_argument \
        ('-V', '--vpid-prefix'
         , help='VPID prefix, default "%(default)s"'
         , default=cfg.get('vpid_prefix', '')
         )
    cmd.add_argument \
        ('-o', '--otp-pin'
         , help='Aladdin 2FA pin, default "%(default)s"'
         , default=cfg.get('otp_pin', '')
         )
    cmd.add_argument \
        ('--version'
         , help='Display version and exit'
         , action='store_true'
         )
    args = cmd.parse_args()
    return args


def print_version_and_exit(args):
    if args.version:
        print("snxconnect version %s by RTKIT" % VERSION)
        sys.exit(0)


def check_username_and_password(args):
    if not args.username or not args.password:
        n = a = None
        try:
            n = netrc()
        except (IOError, NetrcParseError):
            pass
        if n:
            a = n.authenticators(args.host)
        if a:
            username, _, password = a
            if not args.username:
                args.username = username
            if not args.password:
                args.password = password
        if not args.password:
            args.password = getpass('Password: ')


def connect(args):
    print("snxconnect version %s by RTKIT" % VERSION)
    rq = Requester(args)
    rq.print_snx_version()
    if rq.login():
        rq.call_snx()


def main():
    home = os.environ.get('HOME')
    cfg = parse_config_file(home)
    args = parse_args(cfg, home)

    print_version_and_exit(args)
    check_username_and_password(args)

    connect(args)


if __name__ == '__main__':
    main()
