from __future__ import print_function, unicode_literals

import datetime
import os
import os.path
import socket
import ssl
import subprocess
import sys
import time

import rsa

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
from bs4 import BeautifulSoup
from getpass import getpass
from struct import pack, unpack
from subprocess import Popen, PIPE

CHALLENGE_MAX_COUNT = 5


class Requester(object):

    def __init__(self, args):
        self.modulus = None
        self.exponent = None
        self.timeout = None
        self.f = None
        self.snx_info = None
        self.soup = None
        self.purl = None
        self.info = None
        self.extender_vars = None
        self.args = args
        self.jar = j = LWPCookieJar()
        self.has_cookies = False
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if self.args.cookiefile:
            self.has_cookies = True
            try:
                j.load(self.args.cookiefile, ignore_discard=True)
            except IOError:
                self.has_cookies = False
        handlers = [HTTPCookieProcessor(j)]
        if self.args.ssl_noverify:
            handlers.append(HTTPSHandler(context=context))
        self.opener = build_opener(*handlers)
        self.nextfile = args.file

    def print_snx_version(self):
        """ Print snx binary build version. Get build version
            from stdout after call it with the 'usage' option.
        """
        sp = self.args.snxpath
        self.print_if_debug(sp)
        snx = Popen([sp, 'usage'], stdin=PIPE, stdout=PIPE, stderr=PIPE, universal_newlines=True)
        stdout, stderr = snx.communicate('')
        for line in stdout.splitlines():
            line = line.strip()
            if 'build' in line:
                print("Use '%s': Check Point's Linux SNX (%s)" % (sp, line))
                return

    def call_snx(self):
        """ The snx binary usually lives in the default snxpath and is
            setuid root. We call it with the undocumented '-Z' option.
            When everything is well it forks a subprocess and exists
            (daemonize). If an error occurs before forking we get the
            result back on one of the file descriptors. If everything
            goes well, the forked snx process opens a port on
            localhost:7776 (I've found no way this can be configured)
            and waits for us to pass the binary-encoded parameters via
            this socket. It later sends back an answer. It seems to keep
            the socket open, so we do another read to wait for snx to
            terminate.
        """
        sp = self.args.snxpath
        self.print_if_debug(sp)
        if self.args.print_if_debug:
            #            snx = Popen (['strace', '-o', 'strace_snx', '-s', '2000', '-p' ,sp, '-Z'], stdin = PIPE, stdout = PIPE, stderr = PIPE)
            snx = Popen([sp, '-Z'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        else:
            snx = Popen([sp, '-Z'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        stdout, stderr = snx.communicate('')
        rc = snx.returncode
        if rc != 0:
            print("SNX terminated with error: %d %s%s" % (rc, stdout, stderr))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", 7776))
        sock.sendall(self.snx_info)
        answer = sock.recv(4096)
        if self.args.print_if_debug:
            f = open('snxanswer', 'wb')
            f.write(answer)
            f.close()
        print("SNX connected, to leave VPN open, leave this running!")
        remaining = int(self.timeout)
        #        remaining = 70
        try:
            while True:
                # time.sleep(4000000)
                sys.stdout.write("\r                    \r")  # carriage return + clean line
                sys.stdout.write(str(datetime.timedelta(seconds=remaining)))
                remaining = remaining - 1
                if remaining == 600:
                    self.notify("10 minutes remain")
                if remaining < 1:
                    self.notify("Session time has expired")
                    raise KeyboardInterrupt("Time is out")
                sys.stdout.flush()
                time.sleep(1)

            # answer = sock.recv (4096) # should block until snx dies
        except KeyboardInterrupt:
            sys.stdout.write('\b\b\r')
            sys.stdout.flush()
            sys.stdout.write("Shutting down ...\n")
            sys.stdout.flush()
            try:
                sys.exit(0)
            except SystemExit:
                os._exit(0)

    @staticmethod
    def notify(msg):
        try:
            subprocess.run(['notify-send', 'SNX Notification', msg], check=True)
        except (OSError, Exception):
            print("SNX Notification: " + msg)

    def print_if_debug(self, s):
        if self.args.print_if_debug:
            print(s)

    def generate_snx_info(self):
        """ Communication with SNX (originally by the java framework) is
            done via an undocumented binary format. We try to reproduce
            this here. We asume native byte-order but we don't know if
            snx binaries exist for other architectures with a different
            byte-order.
        """
        magic = b'\x13\x11\x00\x00'
        length = 0x3d0
        gw_ip = socket.gethostbyname(self.extender_vars['host_name'])
        gw_int = unpack("!I", socket.inet_aton(gw_ip))[0]
        fmt = b'=4sLL64sL6s256s256s128s256sH'
        self.print_if_debug(self.extender_vars)
        self.timeout = self.extender_vars['timeout']
        info = pack \
            (fmt
             , magic
             , length
             , gw_int
             , self.extender_vars['host_name']
             , int(self.extender_vars['port'])
             , b''
             , self.extender_vars['server_cn']
             , self.extender_vars['user_name']
             , self.extender_vars['password']
             , self.extender_vars['server_fingerprint']
             , 1  # ???
             )
        assert len(info) == length + 8  # magic + length
        self.snx_info = info

    def login(self):
        if self.has_cookies:
            self.print_if_debug("has cookie")
            self.nextfile = 'Portal/Main'
            self.open()
            self.print_if_debug(self.purl)
            if self.purl.endswith('Portal/Main'):
                self.open(self.args.extender)
                self.parse_extender()
                self.generate_snx_info()
                return True
            else:
                # Forget Cookies, otherwise we get a 400 bad request later
                self.jar.clear()
                self.next_file(self.purl)
        self.print_if_debug(self.nextfile)
        print('Visiting login page ...')
        self.open()
        self.print_if_debug(self.purl)
        # Get the RSA parameters from the javascript in the received html
        for script in self.soup.find_all('script'):
            if 'RSA' in script.attrs.get('src', ''):
                self.next_file(script['src'])
                self.print_if_debug(self.nextfile)
                break
        else:
            print('No RSA javascript file found, cannot login')
            return
        print('Fetching RSA javascript file ...')
        self.open(do_soup=False)
        self.parse_rsa_params()
        if not self.modulus:
            # Error message already given in parse_rsa_params
            return
        for form in self.soup.find_all('form'):
            if 'id' in form.attrs and form['id'] == 'loginForm':
                self.next_file(form['action'])
                assert form['method'] == 'post'
                break
        self.print_if_debug(self.nextfile)

        self.print_if_debug(self.purl)
        password = rsa.pkcs1.encrypt(self.args.password.encode('UTF-8'), rsa.PublicKey(self.modulus, self.exponent))
        password = ''.join('%02x' % b_ord(c) for c in reversed(password))
        d = dict \
            (password=password
             , userName=self.args.username
             , selectedRealm=self.args.realm
             , loginType=self.args.login_type
             , pin=self.args.vpid_prefix
             , HeightData=self.args.height_data
             )
        self.print_if_debug(urlencode(d))
        print("Sending login information ...")
        self.open(data=urlencode(d))
        self.print_if_debug(self.purl)
        self.print_if_debug(self.info)

        for errorMessage in self.soup.select(".errorMessage"):
            if errorMessage and 'style' in errorMessage.attrs and 'none' not in errorMessage['style']:
                self.print_if_debug(self.soup)
                print("Error: %s" % errorMessage.string)
                return
            if errorMessage and 'style' not in errorMessage.attrs and len(errorMessage.string.strip()) > 0:
                self.print_if_debug(self.soup)
                print("Error: %s" % errorMessage.string)
                return

        while_count = 0
        while 'MultiChallenge' in self.purl:
            d = self.parse_pw_response()
            del d['phoneNumbersSelection']
            del d['SendMethod']
            if while_count == 0 and len(self.args.otp_pin) > 0:
                otp = self.args.otp_pin
            else:
                otp = getpass('One-time Password: ')
            self.print_if_debug("OTP: %s" % otp)
            otp = rsa.pkcs1.encrypt(otp.encode('UTF-8'), rsa.PublicKey(self.modulus, self.exponent))
            otp = ''.join('%02x' % b_ord(c) for c in reversed(otp))
            d['password'] = otp
            d['pin'] = self.args.vpid_prefix
            self.print_if_debug("nextfile: %s" % self.nextfile)
            self.print_if_debug("purl: %s" % self.purl)
            self.print_if_debug("D  %s" % urlencode(d))
            self.open(data=urlencode(d))
            self.print_if_debug("info: %s" % self.info)
            self.print_if_debug("purl2: %s" % self.purl)
            while_count += 1
            if while_count > CHALLENGE_MAX_COUNT:
                print("Error: too many attempts")
                return

        if self.purl.endswith('Login/ActivateLogin'):
            print('Closing previous connection')
            self.open('sslvpn/Login/ActivateLogin?ActivateLogin=activate')

        if self.purl.endswith('Portal/Main'):
            if self.args.save_cookies:
                self.jar.save(self.args.cookiefile, ignore_discard=True)
            self.print_if_debug("purl: %s" % self.purl)
            print("Fetching extender information ...")
            self.open(self.args.extender)
            self.print_if_debug(self.purl)
            self.print_if_debug(self.info)
            self.parse_extender()
            self.generate_snx_info()
            return True
        else:
            print("Unexpected response, looking for MultiChallenge or Portal")
            self.print_if_debug("purl: %s" % self.purl)
            self.print_if_debug(getattr(self.soup.find('span', attrs={'class': 'errorMessage'}), 'string', ''))
            if not self.soup.find('span', attrs={'class': 'errorMessage'}):
                self.print_if_debug(self.soup)
            return

    def next_file(self, filename):
        if filename.startswith('/'):
            self.nextfile = filename.lstrip('/')
        elif filename.startswith('http'):
            self.nextfile = filename.split('/', 3)[-1]
        else:
            dir_path = self.nextfile.split('/')
            dir_path = dir_path[:-1]
            fn = filename.split('/')
            self.nextfile = '/'.join(dir_path + fn)
            # We might try to remove '..' elements in the future

    def open(self, filepart=None, data=None, do_soup=True):
        filepart = filepart or self.nextfile
        url = '/'.join(('%s:/' % self.args.protocol, self.args.host, filepart))
        self.print_if_debug(url)
        if data:
            data = data.encode('ascii')
        rq = Request(url, data, headers={'User-Agent': self.args.useragent})
        self.f = f = self.opener.open(rq, timeout=10)
        self.print_if_debug(f)
        if do_soup:
            # Sometimes we get incomplete read. So we read everything
            # the server sent us and hope this is ok. Note: This means
            # we cannot pass the file to BeautifulSoup but need to read
            # everything here.
            try:
                page = f.read()
            except IncompleteRead as e:
                page = e.partial
            self.soup = BeautifulSoup(page, "lxml")
        #            self.debug(self.soup)
        self.purl = f.geturl()
        self.info = f.info()

    def parse_extender(self):
        """ The SNX extender page contains the necessary credentials for
            connecting the VPN. This information then passed to the snx
            program via a socket.
        """
        for script in self.soup.find_all('script'):
            text = script.text or script.string or ""
            if '/* Extender.user_name' in text:
                break
        else:
            print("Error retrieving extender variables")
            return
        line = None
        for line in text.split('\n'):
            if '/* Extender.user_name' in line:
                break
        stmts = line.split(';')
        self.print_if_debug(stmts)
        vars_ext = {}
        for stmt in stmts:
            try:
                lhs, rhs = stmt.split('=')
            except ValueError:
                break
            try:
                lhs = lhs.split('.', 1)[1].strip()
            except IndexError:
                continue
            rhs = rhs.strip().strip('"')
            self.print_if_debug(rhs)
            vars_ext[lhs] = rhs.encode('utf-8')
        self.extender_vars = vars_ext

    def parse_pw_response(self):
        """ The password response contains another form where the
            one-time password (in our case received via a message to the
            phone) must be entered.
        """
        self.print_if_debug(self.soup.find_all('form'))
        self.print_if_debug(self.soup)
        form = None
        for form in self.soup.find_all('form'):
            self.print_if_debug(form)
            if 'name' in form.attrs and form['name'] == 'MCForm':
                self.next_file(form['action'])
                assert form['method'] == 'post'
                break
        d = {}
        for input_el in form.find_all('input'):
            if input_el.attrs.get('type') == 'password':
                continue
            if 'name' not in input_el.attrs:
                continue
            if input_el['name'] in ('password', 'btnCancel'):
                continue
            d[input_el['name']] = input_el.attrs.get('value', '')
        return d

    def parse_rsa_params(self):
        keys = ('modulus', 'exponent')
        vars_rsa = {}
        for line in self.f:
            line = line.decode('utf-8')
            for k in keys:
                if 'var %s' % k in line:
                    val = line.strip().rstrip(';')
                    val = val.split('=', 1)[-1]
                    val = val.strip().strip("'")
                    vars_rsa[k] = val
                    break
            if len(vars_rsa) == 2:
                break
        else:
            print('No RSA parameters found, cannot login')
            return
        self.print_if_debug(repr(vars_rsa))
        self.modulus = int(vars_rsa['modulus'], 16)
        self.exponent = int(vars_rsa['exponent'], 16)


if sys.version_info >= (3,):
    def b_ord(x):
        return x
else:
    def b_ord(x):
        return ord(x)
