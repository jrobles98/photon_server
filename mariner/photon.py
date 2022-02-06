#!/usr/bin/python3

"""
Source of the code of this file: https://www.improwis.com/projects/sw_PhotonControl/photon.py
"""


import argparse
import errno
import os
import re
import select
import socket
import string
import struct
import sys
import getopt
import time
import datetime
import binascii


# default name, assumed to be in /etc/hosts
PHOTON_NAME='photon1'

# default UDP port, fixed in Photon firmware
PHOTON_PORT=3000

# network interface to bind the socket
PHOTON_BINDTO='0.0.0.0'

# comm timeout, 800 msec - plenty of time on a LAN, even wifi
PHOTON_TIMEOUT=0.8

# retries before fail (autodetect-only now; TODO: all send-response pairs)
PHOTON_RETRIES=3

photon_name=PHOTON_NAME
photon_addr=''

# verbosity
VERB=0

softbreak=False
dobreak=False
initdone=False

def sock_bind(addr):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(addr)
        except socket.error as e:
            if e.errno == errno.EADDRNOTAVAIL:
                raise Error(
                    ('Address %s:%d not available.\n\n'
                     'Try running:\n'
                     'linux$ sudo ifconfig eth0:0 %s\n'
                     'osx$   sudo ifconfig en0 alias %s '
                     '255.255.255.0\n\n'
                     '(adjust eth0 or en0 to taste. see "ifconfig -a" output)')
                    % (addr[0], addr[1], addr[0], addr[0]))
            if e.errno == errno.EADDRINUSE:
                raise Error(
                    ('Address %s:%d in use.\n'
                     'Make sure no other IGORCONF server is running.') % addr)
            if e.errno == errno.EACCES:
                raise Error(('No permission to bind to %s:%d.\n'
                             'Try running with sudo.') % addr)
            raise
        return sock

# alternative with signal handler: https://stackoverflow.com/questions/4205317/capture-keyboardinterrupt-in-python-without-try-except
def kbdbreak():
    print('ctrl-c break!')
    if softbreak: dobreak=True
    else: exit()

def fail():
    print('Unknown failure!')
    exit()

def udp_init_raw():
    global ph_sock
    global initdone
    if initdone: return
    ph_sock=sock_bind((PHOTON_BINDTO,PHOTON_PORT))
    ph_sock.settimeout(PHOTON_TIMEOUT); # 800 msec timeout
    initdone=True

def udp_init():
    global ph_sock
    global initdone
    global photon_addr
    if initdone: return
    udp_init_raw()
    try:
      photon_addr=socket.gethostbyname(photon_name)
    except:
      print('ERROR: can not resolve printer name:',photon_name)
      print('You may like to add your printer\'s IP to /etc/hosts.')
      print('Aborting.')
      exit()
    if VERB >= 1: print('address of "'+photon_name+'" is '+photon_addr)
    initdone=True

def udp_send(msg):
    if type(msg) is str:
      msg=bytearray(msg,'utf-8')
    if VERB > 1: print('SEND:',str(msg),'   to:',photon_addr+':'+str(PHOTON_PORT));
    try:
      ph_sock.sendto(msg,(photon_addr,PHOTON_PORT))
    except KeyboardInterrupt:kbdbreak()
    except socket.error as e:
      print('UDP send failure:',e.errno)
      exit()
    #except:fail()

def udp_broadcast(msg):
    ph_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    if type(msg) is str:
      msg=bytearray(msg,'utf-8')
    if VERB > 1: print('BROADCAST:',msg);
    try:
      ph_sock.sendto(msg,('<broadcast>',PHOTON_PORT))
    except KeyboardInterrupt:kbdbreak()
    except socket.error as e:
      print('UDP broadcast failure:',e.errno)
      exit()
    #except:fail()

def udp_nobroadcast():
    ph_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 0)

def udp_get(forever=False):
    try:
      v=ph_sock.recvfrom(4096)
      if VERB > 1: print('RECV:',v[0]);
      return v
    except KeyboardInterrupt:kbdbreak()
    except socket.error as e:
      if str(e.errno) == 'None':
        if forever: return '',''
        else: exit()
      print('UDP get failure:',str(e.errno))
      exit()
    #except:fail()

def udp_gettxt(forever=False):
    s,_=udp_get(forever=forever)
#    if VERB > 1: print('RECV:',s)
    if not s=='': s=s.decode('utf-8')
    s=s.strip()
    return s

def udp_getall():
    while True:
      data,addr=udp_get()
#      if VERB > 1: print('RECV:',data)
      if data=='': break

# receive autodetect responses
# ok MAC:XX:XX:XX:XX:XX:XX IP:X.X.X.X VER:V1.4.1 ID:XX,XX,XX,XX,XX,XX,XX,XX NAME:ZWLF
def udp_getalltxt():
    while True:
      s=udp_gettxt(forever=True)
      if s=='': break
      print('recv: ',s)

# listen, return true if detected, false if timeouted
def udp_getautodetect():
    global photon_name
    global photon_addr
    photon_name=''
    photon_addr=''
    while True:
      s=udp_gettxt(forever=True)
      if s=='M99999': continue
      if s=='':
#        print("ERROR: no printer found on the LAN.")
#        print("Aborting.")
#        exit()
        print("autodetect timeouted")
        return False
      if VERB > 1: print('recv: ',s)
#      if s[:3]!='ok ':
      if not isok(s):
        print("Unexpected response: \""+s+"\", doesn't start with 'ok ', ignoring")
        continue
      ss=s.split(' ')
      #print(ss)
      if ss[2][:3] != 'IP:':
        print("Unexpected response: \""+s+"\", third word does not start with 'IP:', ignoring")
        continue
      #print(ss[2],ss[2][3:])
      photon_addr=ss[2][3:]
      photon_name=photon_addr
      print('Autodetected:',photon_addr)
      time.sleep(0.1)
      udp_nobroadcast()
      return True


# just run the detection, spit out raw responses
def photon_detect():
    udp_init_raw()
    udp_broadcast(b'M99999')
    while True:
      s=udp_gettxt(forever=True)
      if s=='M99999': continue
      if s=='': break
      print('recv: ',s)

# autodetect printer location
# beware in case of multiple printers: first come first serve!
def photon_autodetect():
    udp_init_raw()
    for t in range(PHOTON_RETRIES):
      udp_broadcast(b'M99999')
      if udp_getautodetect():return
    # failed
    print("ERROR: no printer found on the LAN.")
    print("Aborting.")
    exit()




def photon_cmd_long(cmd):
    udp_init()
    udp_send(cmd)
    s = ""
    while True:
      s+=udp_gettxt(forever=True)
      if s=='': break
      print(s)
    return s

def photon_cmd(cmd):
    udp_init()
    udp_send(cmd)
    s=udp_gettxt(forever=True)
    print(s)
    return s



def sortElement(val): 
    return val[0]

# list remote files
def photon_ls(fnlen=''):
    udp_init()
    udp_send('M20')
    fsize=-1
    fl=[]
    while True:
      s=udp_gettxt(forever=True)
      if s=='': break
      if s=='Begin file list': continue
      if s=='End file list': continue
      spos=s.rfind(' ')
      try:
        fs=int(s[spos:len(s)])
        fl.append((s[0:spos],fs))
        if fnlen != '':
          if fnlen==s[0:spos]: fsize=fs;
#        print('{:>12,}'.format(fs,','),s[0:spos])
      except:
        print(s)
      #print(s)
    fl.sort(key=sortElement)
#    print(fl)
#    if fnlen != '':
#      return fsize
    for fn,fs in fl:
      print('{:>12,}'.format(fs,','),' ',fn)
    return fsize


# remove remote file
def photon_rm(fn):
    photon_cmd_long('M30 '+fn)


# print remote file
def photon_print(fn):
    #TODO: optional are-you-sure query
    photon_cmd_long("M6030 '"+fn+"'")


# get SD printing byte xxx/yyy
def photon_stat():
    s=photon_cmd('M27')
    #print(s)
    if s[0:17] == 'SD printing byte ':
      a=s[17:].split('/')
      idone=int(a[0])
      ifrom=int(a[1])
      iperc=100*idone/ifrom
      #print(a,idone,ifrom,iperc)
      print('Percent: {:6.4}'.format(iperc))


def getfilelen(s):
#   RECV: b'ok L:4096'
#   [b'ok L', b'4096']
    l=s.split(':')
    if l[0] == 'ok L':
      return int(l[1])
    else:
      print('ERROR: unexpected response:',s)
      return -1

def isok(s):
    #print(s[0:2])
    if s[0:2] == 'ok': return True
    return False

def err(s,s2):
    print('ERROR:',s,s2)
    exit()

# file transfer protocol:
# last 6 bytes: XX XX XX XX YY ZZ
# XX XX XX XX: big-endian offset
# YY: checksum, all payload and offset XORed together
# ZZ: 0x83, magic

def photon_getfile(locfn,remfn):
    global softbreak
    f=open(locfn,'wb')
    softbreak=True

    udp_init()
    udp_send('M22')
    s=udp_gettxt()
    if not isok(s): err('M22 fail',s)

    udp_send('M6032 \''+remfn+'\'')
    s=udp_gettxt()
    if not isok(s): err('M6032 fail',s)
    l=getfilelen(s)
    remain=l
    offs=0
    retr=0
    print('Length:',l)

    tstart=datetime.datetime.now();

    while remain > 0:
      if dobreak: break
      udp_send('M3000')
#      udp_send(b'M3001 I'+str(offs).encode('ascii'))
      d,_=udp_get(forever=True)
      if(len(d)<6):
        print('RETRYING')
        udp_send(b'M3001 I'+str(offs).encode('ascii'))
        retr=retr+1
        d,_=udp_get(forever=True)
        if(len(d)<6):
          print('RETRYING AGAIN')
          udp_send(b'M3001 I'+str(offs).encode('ascii'))
          retr=retr+1
          d,_=udp_get(forever=True)
          if(len(d)<6):
            print('Too many retries, FAIL')
            break
      dd=bytearray(d[0:len(d)-6])
      dc=bytearray(d[len(d)-6:len(d)])
      dxor=dc[4]
      doffs=int.from_bytes(dc[0:3], byteorder='little', signed=False)
#      print(binascii.hexlify(dc[0:4]).decode('ascii'),doffs)
      cxor=0
      for c in dd: cxor=cxor ^ c
      for c in dc[0:4]: cxor=cxor ^ c
#      print(binascii.hexlify(dc).decode('ascii'),doffs,dxor,cxor)
      if cxor != dxor:
        print('CHECKSUM ERROR!')
        print(binascii.hexlify(dc).decode('ascii'),doffs,dxor,cxor)
        break
#      print(binascii.hexlify(dc).decode('ascii'),doffs,dxor,cxor)
      f.write(dd)
      offs=offs+len(dd)
      remain=remain-len(dd)
#      print(len(d),len(dd),remain)
      print(retr,remain,end='   \r')
    #
    print('done   ')
    udp_send('M22')
    udp_getalltxt()
    f.close()
    tdiff=datetime.datetime.now()-tstart
    print()
    print('Remote file:    ',remfn)
    print(' to local file: ',locfn)
    print('Duration (sec):        ','{:>12,}'.format(round(tdiff.total_seconds(),2)))
    print('Speed (b/s):        ','{:>12,}'.format(round((l-remain)/tdiff.total_seconds())))
    print('Transferred (bytes):','{:>12,}'.format(l-remain))
    print('Retries:            ','{:>12}'.format(retr))
    if dobreak: exit()

""" 000000003b83 0 59 59
1286 1280 2816
SEND: b'M3000'
000500000583 1280 5 5
1286 1280 1536
SEND: b'M3000'
000a00003883 2560 56 56
1286 1280 256
SEND: b'M3000'
000f00000e83 3840 14 14
262 256 0

chk: 000000003b83 0 59
chk: 000005000583 1280 5
chk: 00000a003883 2560 56
chk: 00000f000e83 3840 14

     000000003b83 0 59 59
chk: 000000003b83 0 59
     000500000583 1280 5 5
chk: 000500000583 1280 5
     000a00003883 2560 56 56
chk: 000a00003883 2560 56
     000f00000e83 3840 14 14
chk: 000f00000e83 3840 14

"""

def photon_putfile(locfn,remfn):
    global softbreak

    udp_init()
    udp_send('M22')
    s=udp_gettxt()
    if not isok(s): err('M22 fail',s)

    l=os.stat(locfn).st_size
    #return

    softbreak=True
    udp_send('M28 '+remfn)
    s=udp_gettxt()
    if not isok(s): err('M28 fail',s)

    f=open(locfn,'rb')
    remain=l
    offs=0
    retr=0
    print('Length:',l)
    #
    tstart=datetime.datetime.now();
    while remain > 0:
#    while offs<l:
      if dobreak: break
      dd=f.read(1280)
      #print(dd,len(dd),offs)
      remain=remain-len(dd)
      dc=bytearray(offs.to_bytes(length=4, byteorder='little'))
      cxor=0
      for c in dd: cxor=cxor ^ c
      for c in dc: cxor=cxor ^ c
      dc.append(cxor)
      dc.append(0x83)
      #print('chk:',binascii.hexlify(bytearray(dc)).decode('ascii'),offs,cxor)
      offs=offs+len(dd)

      udp_send(dd+dc)
      s=udp_gettxt(forever=True)
      #print(s)
      print(retr,remain,end='   \r')
      #print('chk:',binascii.hexlify(bytearray(dc)).decode('ascii'),offs,cxor)
      if s != 'ok':
        print('\nRECV:',s)
        print('Retrying')
        retr=retr+1
        udp_send(dd+dc)
        s=udp_gettxt(forever=True)
        if s != 'ok':
          print('Retrying, 2nd time')
          retr=retr+1
          udp_send(dd+dc)
          s=udp_gettxt(forever=True)
          if s != 'ok':
            print("Error uploading, too many retries")
            break

#      print(s)
    #
    print('done   ')
    udp_send('M29')
    udp_getalltxt()
    f.close()

    tdiff=datetime.datetime.now()-tstart
    print()
    fsize=photon_ls(remfn)
    print()
    print('Local file:      ',locfn)
    print(' to remote file: ',remfn)
    print('Duration (sec):        ','{:>12,}'.format(round(tdiff.total_seconds(),2)))
    print('Speed (b/s):        ','{:>12,}'.format(round((l-remain)/tdiff.total_seconds())))
    print('Transferred (bytes):','{:>12,}'.format(l-remain))
    print('Remote file:        ','{:>12,}'.format(fsize))
    if fsize != (l-remain):    print('                     SIZE MISMATCH!!!')
    print('Retries:            ','{:>12}'.format(retr))
    if dobreak: exit()

"""
[[c|<filename>]] refers to relative path in currently selected directory, [[c|:<filename>]] refers to absolute path
* Operations:
* [[c|M22]] - close file
* [[c|M24]] - resume
* [[c|M25]] - pause
* [[c|M27]] - get status
* [[c|M28 <filename>]] - upload file to printer
* [[c|M29]] - stop print or cancel file upload
* [[c|M30 <filename>]] - delete file from printer
* [[c|M33]] - stop print (?)
* [[c|M114]] - get head position
* [[c|M3000]] - get next file chunk
* [[c|M3001 I<offset>]] - request resend from arbitrary offset from start
* [[c|M4002]] - get printer version
* [[c|M6030 '<filename>']] - start printing
* [[c|M6032 '<filename>']] - download file from printer
* [[c|M99999]] - detect printer (sent by broadcast)

* Configuration, basic - after setting config store it via M8500 or just use it via M8510
* [[c|M8013 I20]] - z-axis max speed (mm/s)
* [[c|M8015 I3]] - z-axis zeroing speed, first pass
* [[c|M8015 T2]] - z-axis slow speed, for slow-motion peel (default 2)
* [[c|M8016 I2]] - z-axis zeroing speed, second pass
* [[c|M8016 T3]] - z-axis fast speed, for remain of the total distance and descent to another layer (default 3)
* [[c|M8016 D10]] - delay (milliseconds) between rising and lowering z-axis
* [[c|M8030 I-2]] - LED fan control; 0=always off, -1=always on, -2=on when printing
* [[c|M8030 T-1]] - motherboard fan control; 0=always off, 1=during exposure, -1=always on, -2=when printing
* [[c|M8070 S3]] - z-axis lift, slow-motion/release distance (default 3)
* [[c|M8070 Z6]] - z-axis lift, total (slow+fast) distance (default 6)
* [[c|M8083 I1]] - limit position; 0=limit switch position is z=0, 1=z-offset set by M8084
* [[c|M8084 Z0]] - limit position offset, usually 0 or a positive number
* [[c|M8093 I1]] - enable M8093 to dump debug to a file (Only works in recent firmwares)
* [[c|M8489 I256]] - set max fan speed (default 256) (todo: test)
* [[c|M8500]] - store and use config
* [[c|M8510]] - use config immediately but don't store (for testing)
* [[c|M8511]] - revert to stored configuration
* [[c|M8512 "configFile.gcode"]] - dumps the current EEPROM config data into a file[[ref|https://github.com/Photonsters/anycubic-photon-docs/blob/master/firmware/eeprom_dump.gcode]]
* [[c|M8513]] - reset printer config (delete all parameters)

* Configuration, cosmetic/behavioral
* [[c|M7506 I636264]] - user interface colors; T0=normal, T1=inverted, T2=flip EEPROM saved mode
* [[c|M8085 I5000]] - boot logo duration; min.5000, max.6000 milliseconds
* [[c|M8085 T0]] - screensaver time in seconds; 0=screensaver off
* [[c|M8489 P3]] - after completing printing: 0=turn off motors, 1=no action, 2=return to zero then turn off motors (DO NOT USE, crushes printout through display), 3=move to top and turn off motors (defa

* Configuration, extended (do not use if everything works)
* [[c|M8006 I30]] - maximum speed limit (holdover from FDM printer config?)
* [[c|M8007 I15]] - max jerk speed - for reciprociating motion (holdover from FDM printer config?)
* [[c|M8008 I700]] - acceleration; the higher the value the higher the speedup but also noise and risk of losing steps (default 600) (used for z-axis?)
* [[c|M8010 S0.000625]] - mm per step (16 microsteps per step, 2mm lead screw, 1.8-deg/step (200 steps/rotation); default lead/((360/1.8)*16)=0.000625; can be used for fine calibration of z-axis or diffe
* [[c|M8004 I-1]] - z-axis stepper direction; -1=ccw, 1=cw
* [[c|M8005 Z0]] - z-axis manual control direction; 0=normal, 1=reversed
* [[c|M8026 I155]] - z-axis maximum position in mm
* [[c|M8029 I0]] - z-axis limit switch type: 0=unilateral (only Zmin), 2=bilateral (Zmin and Zmax)
* [[c|M8029 T0]] - z-axis limit switch type: 0=normally open (H when open, L when triggered), 1=normally closed (L when open, H when triggered)
* [[c|M8029 S0]] - 0=limit switch for molding support close to the platform, Zmin end 1=Zmax end
* [[c|M8029 C0]] - after zeroing: 0=go to z=0 position, 1=stay in the limit-switch position
* [[c|M8030 S4]] - LED light control; 4=LED on only when exposing image is on the screen
* [[c|M8034 I1]] - SD card folder support; 0=disabled, 1=enabled
* [[c|M8087 I0 T0]] - for external stepper driver; I=direction signal settling time (nanoseconds), T=minimum time for pulse (nanoseconds); I0 T0 for no driver board, I100000 T0 for THB7128 and TB6600, I4
"""



# M20           read file list (returns UDPs one per line)
# M22           close file
# M24           resume
# M25           pause
# M27           get status
# M28 <fn>      upload file
# M29           stop print or file upload
# M30 <fn>      delete file
# M33           stop print (?)
# M114          query Z
# M3000         request next file chunk
# M3001         request resend
# M4002         get printer version
# M6030         start printing
# M6032 '<fn>'  download file

# M33 I5


def help():
    print("Usage:")
#    print('\n')
    print("""photon.py <command> <parameters>
 file commands:
   put <filename>          uploads local file to printer; synonyms: post,send,upload
   get <filename>          downloads file from printer
   rm <filename>           removes file from printer; synonym: del
   ls                      lists files on printer; synonym: dir
 printer status commands:
   detect                  detects printers on network; synonyms: scan,find
   ver                     shows printer version; synonym: version
   pos                     shows printer head position; synonym: position
   stat                    shows printing job status; synonym: status
 print control commands:
   print <filename>        starts printing file (DANGEROUS - check if plate is ready); synonyms: run,exec
   abort                   stops printing; synonym: stop,cancel
   pause                   pauses printing
   resume                  resumes paused printing; synonym: continue
   STOP                    emergency stop, immediately stops printing without subsequent head lift (untested); synonym: estop
   beep                    make the printer's double-beep
 printer control commands (use quotes if contain spaces):
   g "<code>"              sends G-code, converts to uppercase (for commands/parameters)
   G "<code>"              sends G-code, preserves case (for filenames)

 connection parameters:
   -a                      autodetect IP address (first come first serve)
   -n <printername>        use printer name or IP address (default: '"""+PHOTON_NAME+"""')
   -I <interface>          bind to network interface (default: """+PHOTON_BINDTO+""")
 filename parameters:
   -l <locfile>            local file name override
   -r <remfile>            remote file name override
 verbosity:
   -v                      verbose
   -vv                     more verbose
   -vvv                    even more verbose

 parameters -a and -n can precede the <command>
 (to facilitate use of "alias" for multiple printers or to always force autodetect)

 caution: when putting in a file, remove another (or same-name) file first
          added files do not seem to show on the printer interface
""")
    exit()


maincmd_short=['ls','dir', 'ver','version', 'stat','status', 'pos','position', 'detect','scan','find', 'stop','abort','cancel', 'pause', 'resume','continue', 'STOP','estop', 'beep']
maincmd=      ['ls','dir', 'ver','version', 'stat','status', 'pos','position', 'detect','scan','find', 'stop','abort','cancel', 'pause', 'resume','continue', 'STOP','estop', 'beep',
               'get', 'put','post','send','upload', 'rm','del', 'print','run','exec', 'g', 'G']


def parseopts(argv):
    try:
#      opts,args=getopt.getopt(argv,'l:r:v',['locfile=','remfile=','verbose'])
      opts,args=getopt.getopt(argv,'l:r:n:i:va',['locfile=','remfile=','name=','interface=','verbose','autodetect'])
    except getopt.GetoptError:
      print('getopt error: error parsing arguments')
      print()
      help()
    return opts,args


def main(argv):
    global VERB
    global photon_name
    global PHOTON_BINDTO
    argn=0

    if len(argv)<1: help()
    if argv[0]=='-h': help()
    if argv[0]=='--help': help()

    if argv[0]=='-a':
      photon_autodetect()
      argv=argv[1:]
    if argv[0]=='-n':
      photon_name=argv[1]
      argv=argv[2:]

#    print(len(argv))
#    print(argv[0])

    locfile=''
    remfile=''
    fname=''
    verb=0

#    if argv[argn]=='-n':
#      photon_name=argv[argn+1]
#      argn=argn+2

    cmd=''
    parm=''
    if argv[0] in maincmd:
      cmd=argv[0]
      if len(argv)>1: parm=argv[1]
      argv=argv[1:]
      if not cmd in maincmd_short:
        argv=argv[1:]

    opts,args=parseopts(argv)

    if cmd=='':
       cmd=args[0]
       args=args[1:]
    if not cmd in maincmd:
      print('Unknown command: ',cmd)
      print()
      help()

    #cmd=cmd.decode('utf-8')
    if parm=='':
      if len(args)>0: parm=args[0]
#    print('parm:',parm)
    #parm=bytearray(parm,'utf-8')

#    print('opts:',opts)
#    print('args:',args)
    for opt, arg in opts:
      #if opt == '-h': help()
      #if opt in ('-l', 
#      print('opt:',opt,'arg:',arg)

      if opt in ('-l','--locfile'):
        locfile=arg

      elif opt in ('-r','--remfile'):
        remfile=arg

      elif opt in ('-n','--name'):
        photon_name=arg

      elif opt in ('-I','--interface'):
        PHOTON_BINDTO=arg

      elif opt in ('-a','--auto'):
        photon_autodetect()

      elif opt in ('-v','--verbose'):
        VERB=VERB+1


#    print('-----------')
#    print()


    if cmd=='ls' or cmd=='dir':
      photon_ls()
      exit()

    if cmd=='ver' or cmd=='version':
      photon_cmd(b'M4002')
      exit()

    if cmd=='stat' or cmd=='status':
      photon_stat()
      exit()

    if cmd=='pos' or cmd=='position':
      photon_cmd(b'M114')
      exit()

    if cmd=='STOP' or cmd=='estop':
      photon_cmd(b'M112')
      exit()

    if cmd=='abort' or cmd=='stop' or cmd=='cancel':
      photon_cmd(b'M33 I5') #M33 seems to lock up the printer..? but it unlocks on touch on display
      exit()

    if cmd=='pause':
      photon_cmd(b'M25')
      exit()

    if cmd=='resume' or cmd=='continue':
      photon_cmd(b'M24')
      exit()

    if cmd=='beep':
      photon_cmd(b'M300')
      exit()

    if cmd=='detect' or cmd=='scan' or cmd=='find':
      photon_detect()
      exit()

    if cmd=='g':
      return(photon_cmd(str(parm).upper()))

    if cmd=='G':
      return(photon_cmd(parm))

    if cmd in ('get', 'put','post','send','upload', 'rm','del', 'print','run','exec'):
      fname=parm
#      if locfile=='':
#        if remfile=='': fname=parm
      if locfile=='': locfile=fname
      if remfile=='': remfile=fname
      remfile=os.path.basename(remfile)
      # debug
      print('fn: ',fname)
      print('loc:',locfile)
      print('rem:',remfile)

      if remfile=='':
        print('ERROR: File not specified.')
        exit()

      if cmd == 'get':
        photon_getfile(locfile,remfile)
        exit()

      if cmd == 'put' or cmd == 'post' or cmd == 'send' or cmd == 'upload':
        photon_putfile(locfile,remfile)
        exit()

      if cmd == 'rm' or cmd == 'del':
        photon_rm(remfile)
        exit()

      if cmd == 'print' or cmd=='run' or cmd=='exec':
        photon_print(remfile)
        exit()





if __name__ == "__main__":
   main(sys.argv[1:])






