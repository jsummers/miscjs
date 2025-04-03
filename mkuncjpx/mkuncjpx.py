#!/usr/bin/env python3
# mkuncjpx.py: An attempt to generate an example of an
# uncompressed JPEG 2000 file. Public domain /js

# Write a string (or whatever)
def wr(f, s):
    f.write(s)

# Write hex bytes parsed from a string
def wh(f, s):
    f.write(bytes.fromhex(s))

# Write a box header
def startbox(f, box_type, payload_len):
    f.write((8+payload_len).to_bytes(4, byteorder='big'))
    wr(f, box_type)

f = open('unctest.jpf', 'wb')

startbox(f, b'jP  ', 4)
wh(f, '0d 0a 87 0a') # standard contents of signature box

startbox(f, b'ftyp', 12)
wr(f, b'jpx ') # brand
wh(f, '00000000') # version
wr(f, b'jpx ') # compatibility brand(s)

startbox(f, b'rreq', 25)
wh(f, '01') # mask size in bytes
wh(f, 'fc 04') # FUAM, DCM masks
wh(f, '0006') # number of standard feature items
wh(f, '0008 80') # 8: no opacity
wh(f, '000c 40') # 12: contiguous
wh(f, '0012 20') # 18: no layers needed
wh(f, '0014 10') # 20: 1 codestream per layer
wh(f, '001f 08') # 31: scaling not req'd
wh(f, '002e 04') # 46: sRGB-gray
wh(f, '0000') # number of vendor feature items

startbox(f, b'jpch', 22)
startbox(f, b'ihdr', 14)
wh(f, '00000008 0000000c') # height, width
wh(f, '0001') # number of components
wh(f, '07') # bits/component, minus 1
wh(f, '00') # compression type: 0 = uncompressed
wh(f, '00') # flag for unknown colourspace
wh(f, '00') # flag for intellectual property

startbox(f, b'jplh', 23)
startbox(f, b'cgrp', 15)
startbox(f, b'colr', 7)
wh(f, '01') # 1 = using an enumerated colour type
wh(f, '00') # precedence
wh(f, '01') # APPROX: 1 = accurate
wh(f, '00000011') # 17 = sRGB-gray

startbox(f, b'jp2c', 96)
wh(f, 'ff ff ff ff ff ff ff ff ff ff ff ff')
wh(f, 'ff ff 00 ff 00 00 00 ff 00 ff 00 ff')
wh(f, 'ff ff 00 ff 00 ff 00 ff 00 ff 00 ff')
wh(f, 'ff ff 00 ff 00 ff 00 ff ff 00 ff ff')
wh(f, 'ff ff 00 ff 00 00 00 ff 00 ff 00 ff')
wh(f, 'ff ff 00 ff 00 ff ff ff 00 ff 00 ff')
wh(f, '00 00 00 ff 00 ff ff ff 00 ff 00 ff')
wh(f, 'ff ff ff ff ff ff ff ff ff ff ff ff')

f.close()
