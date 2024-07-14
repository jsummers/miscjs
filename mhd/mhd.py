#!/usr/bin/env python3

# MHD: A script to hex dump multiple files at once
# Copyright (C) 2024 Jason Summers
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sys
import struct

class context:
    def __init__(ctx):
        ctx.offset_from_key = 0
        ctx.nbytes = 16
        ctx.keytype = ''

class file_context:
    def __init__(fctx, ctx):
        fctx.name = 'noname'
        fctx.length = 0
        fctx.isopen = False
        fctx.data = bytearray(ctx.nbytes)
        fctx.datavalid = bytearray(ctx.nbytes)
        fctx.keypos = 0

def onefile_print(ctx, fctx):
    for i in range(ctx.nbytes):
        if fctx.datavalid[i]:
            print("%02x " % (fctx.data[i]), end='')
        else:
            print("   ", end='')

    for i in range(ctx.nbytes):
        if fctx.datavalid[i]:
            if fctx.data[i]>=32 and fctx.data[i]<=126:
                print("%c" % (fctx.data[i]), end='')
            else:
                print(".", end='')
        else:
                print(" ", end='')

    print(" %s" % (fctx.name))


def onefile_readbytes(ctx, fctx):
    if not fctx.isopen:
        return

    pos_to_read_from = fctx.keypos + ctx.offset_from_key
    pos_to_read_to = 0
    nbytes_to_read = ctx.nbytes

    if pos_to_read_from < 0:
        pos_to_read_to = pos_to_read_to - pos_to_read_from
        nbytes_to_read = nbytes_to_read + pos_to_read_from
        pos_to_read_from = 0

    if pos_to_read_from+nbytes_to_read > fctx.length:
        nbytes_to_read = fctx.length-pos_to_read_from

    if pos_to_read_from > fctx.length:
        pos_to_read_from = fctx.length
        nbytes_to_read = 0

    if nbytes_to_read<0:
        nbytes_to_read = 0

    fctx.inf.seek(pos_to_read_from, 0)

    tmpbytes = fctx.inf.read(nbytes_to_read)

    for k in range(nbytes_to_read):
        fctx.data[pos_to_read_to+k] = tmpbytes[k]
        fctx.datavalid[pos_to_read_to+k] = 1

def invalidate_file(fctx):
    if not fctx.isopen:
        return
    fctx.inf.close()
    fctx.isopen = False

def calc_com_keypos(ctx, fctx):
    if not fctx.isopen:
        return
    if fctx.length<3:
        invalidate_file(fctx)
        return

    fctx.inf.seek(0, 0)
    tmpbytes = fctx.inf.read(3)
    if tmpbytes[0]==0xe9:
        e0 = struct.unpack("<h", tmpbytes[1:3])
        fctx.keypos = 3 + e0[0];
    elif tmpbytes[0]==0xeb:
        e0 = struct.unpack("b", tmpbytes[1:2])
        fctx.keypos = 2 + e0[0];
    else:
        invalidate_file(fctx)
        return

def calc_exe_keypos(ctx, fctx):
    if not fctx.isopen:
        return
    if fctx.length<28:
        invalidate_file(fctx)
        return

    fctx.inf.seek(0, 0)
    tmpbytes = fctx.inf.read(28)
    e0,e2,e4,e6,e8,e10,e12,e14,e16,e18,e20,e22,e24,e26 = \
        struct.unpack("<HHHHHHHhHHHhHH", tmpbytes)

    if e0!=0x5a4d and e0!=0x4d5a:
        invalidate_file(fctx)
        return

    if ctx.keytype=='execode':
        fctx.keypos = 16*e8
    elif ctx.keytype=='exeoverlay':
        if e4<1:
            invalidate_file(fctx)
            return
        if e2==0:
            fctx.keypos = 512*e4
        else:
            fctx.keypos = 512*(e4-1) + e2
    elif ctx.keytype=='exeentry':
        fctx.keypos = 16*e8 + 16*e22 + e20
    elif ctx.keytype=='exereloc':
        if e24==0 and e6==0:
            fctx.keypos = 28
        else:
            fctx.keypos = e24
    elif ctx.keytype=='exerelocend':
        if e24==0 and e6==0:
            fctx.keypos = 28
        else:
            fctx.keypos = e24 + 4*e6

def onefile_calckeypos(ctx, fctx):
    if ctx.keytype=='' or ctx.keytype=='start':
        fctx.keypos = 0
    elif ctx.keytype=='end' or ctx.keytype=='eof':
        fctx.keypos = fctx.length
    elif ctx.keytype=='execode' or ctx.keytype=='exeoverlay' or \
        ctx.keytype=='exeentry' or ctx.keytype=='exereloc' or \
        ctx.keytype=='exerelocend':
        calc_exe_keypos(ctx, fctx)
    elif ctx.keytype=='comjmp':
        calc_com_keypos(ctx, fctx)
    else:
        raise Exception("Invalid -k option")

def onefile(ctx, fn):
    fctx = file_context(ctx)
    fctx.name = fn

    try:
        fctx.inf = open(fn, "rb")
        fctx.isopen = True
    except:
        pass

    if fctx.isopen:
        fctx.inf.seek(0, 2)
        fctx.length = fctx.inf.tell()

    onefile_calckeypos(ctx, fctx)

    onefile_readbytes(ctx, fctx)

    onefile_print(ctx, fctx)

    if fctx.isopen:
        fctx.inf.close()

def usage():
    print("MHD: Multi-file hex dump utility")
    print("Usage: mhd.py [options] file1 [file2...]")
    print("Options:")
    print(" -n<count>: Number of bytes to dump")
    print(" -o<offset>: Offset of first byte to dump, measured from \"key\" position")
    print(" -keof: Key position = end of file")
    print(" -kexecode, -kexeoverlay, -kexeentry, -kexereloc, -kexerelocend: Special key")
    print("    positions for DOS EXE files")
    print(" -kcomjmp: Special key position for DOS COM files")

def main():
    ctx = context()
    filecount = 0

    for i in range(1, len(sys.argv)):
        if sys.argv[i][0]=='-':
            if sys.argv[i][1]=='o':
                ctx.offset_from_key = int(sys.argv[i][2:])
            elif sys.argv[i][1]=='n':
                ctx.nbytes = int(sys.argv[i][2:])
            elif sys.argv[i][1]=='k':
                ctx.keytype = sys.argv[i][2:]
        else:
            filecount = filecount+1

    if filecount==0:
        usage()
        return

    for i in range(1, len(sys.argv)):
        if sys.argv[i][0]!='-':
            onefile(ctx, sys.argv[i])

main()
