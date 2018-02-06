#!/usr/bin/env python

__version__      = '2.0'
__released__     = '2016-Jan-14'
__author__       = 'David Ford'
__author_email__ = '<david@blue-labs.org>'

import time, sys, re, binascii, traceback, string, pwd
from enum import Enum


def wrap(c):
  return '\x1b[03;36;40m'+c+'\x1b[0m'

def error(s):
  return ('\x1b[1;31m☠ {}\x1b[m'.format(s)) #\u2620
def warning(s):
  return ('\x1b[1;33m\u2639 {}\x1b[m'.format(s))


users = {}


class TTYDIR(Enum):
  stdin = 0
  stdout = 1
  stderr = 2


class UserPid():
  def __init__(self):
    pass

# when we actually build a user terminal, we need to keep track of where their cursor is from moment to moment

class UserTTYs():
  history = {}

  def __init__(self):
    pass
  
  def useradd(self, uid, pid):
    self.history[(uid,pid)] = {TTYDIR.stdin:[], TTYDIR.stdout:[]}
    #print('added tty: {}'.format((uid,pid)))
  
  def __getitem__(self, k):
    if not k in self.history:
      self.useradd(k[0], k[1])
    return self.history[k]
  



"""
Audit record parser
"""
class AuditRecordParser():
  users = {}
  continuations = {}  # dictionary for split lines -- this may happen in between utf glyph bytes
                      # key is (uid, pid, ses)
  
  def __init__(self):
    self.A = ANSI()
    self.T = UserTTYs()

  def feed(self, line):
    ''' a) determine if this is a TTY record or not
        b) get the uid and pid
        c) parse the data record
    '''
    if not line.startswith('type=TTY'):
      return

    _direction=TTYDIR.stdout

    if 'rw=stdin' in line:
      _dir = '\x1b[1;5;7;32;47m\u25b6\x1b[0m'
      _direction = TTYDIR.stdout
    elif 'rw=stdout' in line:
      _dir = '\x1b[32m\u25c0\x1b[0m'
    else:
      _dir = '\u25a0'

    # timestamp
    try:
      audit_ts,audit_record = re.search('audit\(([\d.]+):(\d+)\)', line).groups()
      audit_ts = float(audit_ts)
      audit_record = int(audit_record)
    except Exception as e:
      print(error(line))
      print(error(e))
      return
    
    # uid, pid, session id
    try:
      pid,uid,ses = re.search('pid=(\d+) uid=(\d+) .* ses=(\d+)', line).groups()
      pid = int(pid)
      uid = int(uid)
      ses = int(ses)
    except Exception as e:
      print(error(line))
      print(error(e))
      return
    
    if not uid in users:
      try:
        users[uid] = pwd.getpwuid(uid).pw_name
      except:
        users[uid] = '<unknown:uid:{}>'.format(uid)

    # get a terminal record, new if necessary
    tty = self.T[uid,pid][_direction]
    
    # data
    try:
      data = re.search('data=([A-F0-9]+)', line).group(1)
    except Exception as e:
      print(error(line))
      print(error(e))
      return

    if (uid,pid,ses) in self.continuations:
      _ = self.continuations[(uid,pid,ses)]
      del self.continuations[(uid,pid,ses)]
    else:
      _ = b''
    
    _ += binascii.unhexlify(data)
    try:
      _ = _.decode()
    except:
      # we probably split a glyph in half
      #print('\x1b[1;31msplit utf?\x1b[0m')
      if not (uid,pid,ses) in self.continuations:
        self.continuations[(uid,pid,ses)] = b''
      self.continuations[(uid,pid,ses)] += _
      return

    #print('\x1b[01;30;40mraw line: {!r}\x1b[0m'.format(_))

    for r in self.A.feed(tty, _):
      print('{}\x1b[01;30;40m {:<18.18} {:<14.3f}\u2506\x1b[0m {}\x1b[0m'.format(_dir, users[uid], audit_ts, r))
    

# non ESC codes
simple = {'\x7f':'⌫', # DEL
          '\x08':'⌦', # BS
          '\n':'↲',   # newline (try \u 2bb7, ⮷
          '\r':'↩',   # cr
          '\x04':'␄', '\t':'⇥',
          '\x01':'⏮', '\x02':'⏮',
          '\x03':'✁', # ^C
          '\x04':'❎', # ^D
          '\x0c':'\\f',
          '\x12':'recall', # recall shell history
         }

cursor = {'\x1b[A':'↑', '\x1b[B':'↓', '\x1b[C':'→', '\x1b[D':'←',
          '\x1b[H':'⇱',
         }

ansi_edit = {'\x1b[P':'⌦', # delete from char underneath me moving to right
             '\x1b[K':'↛', # erase from cursor to end of line (inclusive)
             '\x1b[0K':'↛', # erase from cursor to end of line (inclusive)
             '\x1b[1K':'↚', # erase from beginning of line to cursor (inclusive)
             '\x1b[2K':'↮', # erase entire line
         }

ESC = '\x1b'
CSI = '['
OSC = ']'
BEL = '\x07'

colors = { 0:'reset', 1:'bold', 2:'faint', 3:'italic', 4:'underscore', 5:'blink', 6:'blink fast', 7:'reverse', 8:'concealed', 9:'lineout',
          30:'f_black', 31:'f_red', 32:'f_green', 33:'f_yellow', 34:'f_blue', 35:'f_magenta', 36:'f_cyan', 37:'f_white', 38:'rsvd ext. fg', 39:'dflt fg',
          40:'b_black', 41:'b_red', 42:'b_green', 43:'b_yellow', 44:'b_blue', 45:'b_magenta', 46:'b_cyan', 47:'b_white', 48:'rsvd ext. bg', 49:'dflt bg',
          
          #
          #80:'???',

          # 16 color support
          90:'f16_black', 91:'f16_red', 92:'f16_green', 93:'f16_yellow', 94:'f16_blue', 95:'f16_magenta', 96:'f16_cyan', 97:'f16_white', 98:'rsvd ext. fg', 99:'dflt fg',
          100:'b16_black', 101:'b16_red', 102:'b16_green', 103:'b16_yellow', 104:'b16_blue', 105:'b16_magenta', 106:'b16_cyan', 107:'b16_white', 108:'rsvd ext. bg', 109:'dflt bg',
          }

def next_char(s):
  for _ in s:
    yield _




class ANSI():
  def __init__(self):
    pass
  
  def feed(self, tty, line):
    ''' parse the input string unit by unit. a unit is defined as
    an ordinary character, or escape sequence
    '''
    
    output = ''
    
    _g = next_char(line)
    for _ in _g:
      if _ in simple:
        output += wrap(simple[_])

        if _ in ('\n'):
          tty.append(output)
          yield(output)
          output = ''

        continue


      elif _ == ESC:
        __ = next(_g)

        if __ in (CSI,OSC):

          _ += __

          # read Pc until we get a character
          while True:
            __ = next(_g)
            if __ in string.digits or __ in '?;':
              _ += __
              continue
            
            # not a digit or semicolon any more
            _ += __
            break
          
          c,q,d,Pt = re.match('\x1b(.)(\??)([\d;]*)(.*)', _).groups()

          sc = ESC+c
          if c == CSI:
            sc += Pt
            if sc in cursor:
              try:
                d = d is '' and 1 or int(re.match('(\d+)', d).group(1))
              except:
                print('woah, what is d?: {!r}'.format(d))
                sys.exit()
              mxc = cursor[sc] * d
              output += wrap(mxc)

            elif re.fullmatch('[\d;]*m', d+Pt): # try colors
              _c = sorted([int(x) for x in re.findall('(?:(\d*);?)', d) if x])
              if _c == []: _c = [0]
              
              # elicit unknown colors
              __e = False
              __c =  []
              for y in _c:
                try:
                  __c.append(colors[y])
                except:
                  __e = True
                  __c.append(y)

              if __e:
                yield error('unknown color set: {}'.format(__c))

              # show the colors anyway -- note, this can obscure things from us
              output += _
            
            #########
            ######### edits terminal, not fully implemented
            elif re.fullmatch('\d+P', d+Pt): # delete from under me and to the right (Pc times)
              d = d is '' and 1 or int(re.match('(\d+)', d).group(1))
              mxc = ansi_edit[sc] * d
              output += wrap(mxc)
            
            #########
            ######### edits terminal, not fully implemented
            elif re.fullmatch('\d+@', d+Pt): # insert letter following @ here (Pc times)
              d = d is '' and 1 or int(re.match('(\d+)', d).group(1))
              output += next(_g)*d
              # swallow Pt
              continue

            #########
            ######### edits terminal, not fully implemented
            elif re.fullmatch('\d*K', d+Pt): # erase in line, cursor does not move
                                            # 0* from CUR to end (inclusive)
                                            # 1 from begin to CUR (inclusive)
                                            # 2 entire line
                                            # ?0K selective erase to end of line. (1 & 2 similar)
              sc = ESC+c+d+Pt
              d = d is '' and 1 or int(re.match('(\d+)', d).group(1))
              mxc = ansi_edit[sc]
              output += wrap(mxc)
            
            elif c == '[' and q == '?' and Pt == 'l' and d == '25':
              output += wrap('<hide cursor>')
            elif c == '[' and q == '?' and Pt == 'l' and d == '12':
              output += wrap('<stop cursor blink>')
            elif c == '[' and q == '?' and Pt == 'h' and d == '25':
              output += wrap('<show cursor>')
            elif c == '[' and q == '?' and Pt == 'h' and d == '12':
              output += wrap('<start cursor blink>')

            else:
              yield warning('unhandled CSI: c:{!r} q:{!r} d:{!r} Pt:{!r} :: {!r}'.format(c,q,d,Pt,_))

          else: # OSC
            if d == '0;': # change icon name and window title to Pt
                          # continue reading until BEL
              while True:
                __ = next(_g)
                if __ == BEL:
                  break
                Pt += __
              
              yield wrap('\x1b[3;36m<title={!r}/>'.format(Pt))
            else:
              yield warning('unhandled OSC code: {!r}'.format(sc+d+Pt))
            
      else: # unhandled (probaly normal) character
        output += _

    if output:
      tty.append(output)
      yield(output)

"""

# http://www.inwap.com/pdp10/ansicode.txt
def ansi_filter(data, output=False, direction='stdout'):


          '\x1b[F':'↑', 
          '\x1b[3~':'⌦',
          '\\\\':'\\',
          }
    re1 = [
           '(\x1b\[0?K)',# erase to end of line
           '(\x1b\[1K)' ,# erase to beginning of line
           '(\x1b\[2K)' ,# erase entire line
           '(\x1b\[\d*P)' ,# delete Ps characters
           '(\x1bO\w)', #single shift select of next char
          ]

    re3 = {
           '''
           '(\x1b\[0?1;30m)':'<span style="color:grey">',
           '(\x1b\[0?1;31m)':'<span style="color:red">',
           '(\x1b\[0?1;32m)':'<span style="color:green">',
           '(\x1b\[0?1;33m)':'<span style="color:yellow">',
           '(\x1b\[0?1;34m)':'<span style="color:blue">',
           '(\x1b\[0?1;35m)':'<span style="color:magenta">',
           '(\x1b\[0?1;36m)':'<span style="color:cyan">',
           '(\x1b\[0?1;37m)':'<span style="color:white">',
           '(\x1b\[0?1;38m)':'<span style="color:white">',
           '(\x1b\[0?1;39m)':'<span style="color:white">',
           '(\x1b\[0?0?m)':'<span style="color:lightgrey">',     # default color of container
           '''
           '\x1b\]0;.*?\x07':'',                                # OSC  marked unprintable
           '\x1b\[\d*B':'',                                     # CSI  Repeat the preceding graphic character P s times
           '\x1b\[\?1034h':'',                                  # CSI  set window title and icon name
           '\x1b\[\?1002l':'',                                  # CSI  Don’t use Cell Motion Mouse Tracking
           '\x1b\[\?1l':'',                                     # CSI  Use Normal cursor keys
           '\x1b\[\?1049l':'',                                  # CSI  Use Normal Screen Buffer and restore cursor
           '\x1b\[\?2007l':'',                                  # CSI  ?
          }

    # take input line and modify it based on control characters
    
    out = ''
    here = 0
    cursors = False
    history = False
    
    # we MUST know about the terminal to know if \x7f (^?) (delete after) actually does a delete in front of
    
    while here < len(data):
      # start with the simple things
      if data[here] == '\x7f': # DEL next char (we need a history buffer for this)
        here += 1
        cursors = True
        continue

      if data[here] == '\x01': # ^A
        out += esc[data[here]]
        here += 1
        cursors = True
        continue

      if data[here] == '\x02': # ^B
        out += esc[data[here]]
        here += 1
        cursors = True
        continue

      if data[here] == '\x03': # ^C
        out += esc[data[here]]
        here += 1
        cursors = True
        continue

      if data[here] == '\x04': # ^D
        out += esc[data[here]]
        here += 1
        cursors = True
        continue
      
      if data[here] == '\r': # <cr> for stdin
        out += esc['\r']
        here += 1
        if direction == 'stdin':
          out += '\n'
        continue

      if data[here] == '\x1b': # CSI or OSC
        here += 1
        if data[here] == ']': #OSC
          here += 1
          if data[here] == '0': # set window title, ignore until \x07
            while data[here] != '\x07':  # assumes we always get a \7
              here += 1
            here += 1                    # skip past bell
            continue

        if data[here] == '[': #CSI
          if re.match('\[[\d;]+m', data[here:here+7]): # keep color setting
            out += '\x1b'
            while data[here] != 'm':
              out += data[here]
              here += 1
            out += 'm'
            here += 1
            continue
          
          elif re.match('\[\d*A', data[here:here+10]):
            _ = re.match('\[(\d*)A', data[here:here+10]).group(1)
            _c = _ and int(_) or 1
            out += '↑' * _c
            here += len(_)+2
            cursors=True
            continue

          elif re.match('\[\d*B', data[here:here+10]):
            _ = re.match('\[(\d*)B', data[here:here+10]).group(1)
            _c = _ and int(_) or 1
            out += '↓' * _c
            here += len(_)+2
            cursors=True
            continue

          elif re.match('\[\d*C', data[here:here+10]):
            _ = re.match('\[(\d*)C', data[here:here+10]).group(1)
            _c = _ and int(_) or 1
            out += '→' * _c
            here += len(_)+2
            cursors=True
            continue
        
          elif re.match('\[\d*D', data[here:here+10]):
            _ = re.match('\[(\d*)D', data[here:here+10]).group(1)
            _c = _ and int(_) or 1
            out += '←' * _c
            here += len(_)+2
            cursors=True
            continue

      # add regular text
      out += data[here]
      here += 1
      #print(repr(out),here)
      #time.sleep(.25)
      
    if not cursors and not history and direction == 'stdin':
      cli_history[direction].append(out.rstrip('↩\n'))

    return out




# seems that ^c is not seen in audit logs for shells? neither for stdin, nor stdout
"""

p = AuditRecordParser()


for line in sys.stdin.readlines():
    p.feed(line)
