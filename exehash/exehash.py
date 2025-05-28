#!/usr/bin/env python3
# Exehash: Checksum the \"code image\" segment of an EXE file.
# Copyright (C) 2025 Jason Summers
# Terms of use: MIT license. See COPYING.txt.
# Approximate version: 1.00, 2025-05-25

import sys
import struct

class crc32_factory:
    def __init__(self):
        self.tab = [
            0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
            0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
            0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
            0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c ]

class crc32_class:
    def __init__(self, factory):
        self.f = factory
        self.reset()
    def reset(self):
        self.val = 0
    def update(self, data):
        val = self.val ^ 0xffffffff
        for x in data:
            val = (val >> 4) ^ self.f.tab[(val & 0xf) ^ (x & 0xf)];
            val = (val >> 4) ^ self.f.tab[(val & 0xf) ^ (x >> 4)];
        self.val = val ^ 0xffffffff
    def getval(self):
        return self.val
    def oneshot(self, data):
        self.reset()
        self.update(data)
        return self.getval()

class context:
    def __init__(ctx):
        ctx.opt_uppercase = False
        ctx.dict = {}

class exe_info:
    def __init__(self):
        self.is_ext_exe = False

class file_context:
    def __init__(fctx, ctx):
        fctx.name_friendly = '?'
        fctx.isopen = False
        #fctx.valid_dos_exe = False
        fctx.hash = 0
        fctx.codesize = 0
        fctx.filesize = 0
        fctx.ffmt = 'ERR'
        fctx.msg = 'ERR'
        fctx.file_id = 'UNK'
        fctx.hash_strat = 0 # 0=none 1=whole file 2=DOSEXE 3=Ext.EXE

def detect_and_decode_ext_exe(ctx, fctx, ei):
    if fctx.filesize<66:
        return
    if fctx.codepos>0 and fctx.codepos<64:
        return
    if ei.reloc_pos>0 and ei.reloc_pos<64:
        return

    fctx.inf.seek(60, 0)
    tmpbytes2 = fctx.inf.read(4)
    ext_hdr_pos = (struct.unpack("<L", tmpbytes2))[0]
    if ext_hdr_pos==0 or ext_hdr_pos<64 or \
        ext_hdr_pos>(fctx.filesize-4):
        return

    fctx.inf.seek(ext_hdr_pos, 0)
    tmpbytes3 = fctx.inf.read(4)
    if tmpbytes3[0:2]==b'NE':
        ei.is_ext_exe = True
        fctx.ffmt = 'EXE-NE'
    elif tmpbytes3[0:4]==b'PE\0\0':
        ei.is_ext_exe = True
        fctx.ffmt = 'EXE-PE'
    elif tmpbytes3[0:2]==b'LX':
        ei.is_ext_exe = True
        fctx.ffmt = 'EXE-LX'
    elif tmpbytes3[0:2]==b'LE':
        ei.is_ext_exe = True
        fctx.ffmt = 'EXE-LE'

    if ei.is_ext_exe:
        fctx.hash_strat = 3
        fctx.codepos = 60
        fctx.codesize = fctx.filesize - fctx.codepos

def decode_dos_exe(ctx, fctx, ei):
    fctx.ffmt = 'EXE-DOS'

    if fctx.codepos > fctx.filesize:
        fctx.msg = 'BAD-EXE-MISC'
        return

    if ei.e4<1:
        fctx.msg = 'BAD-EXE-MISC'
        return

    if ei.e2==0:
        codeend = 512*ei.e4
    else:
        codeend = 512*(ei.e4-1) + ei.e2

    if codeend > fctx.filesize:
        fctx.msg = 'BAD-EXE-TRUNCATED'
        return

    fctx.codesize = codeend - fctx.codepos
    fctx.hash_strat = 2

def detect_and_decode_exe(ctx, fctx):
    if fctx.filesize<28:
        return

    ei = exe_info()
    fctx.inf.seek(0, 0)
    tmpbytes = fctx.inf.read(28)
    ei.e0,ei.e2,ei.e4,ei.e6,ei.e8,ei.e10,ei.e12,ei.e14, \
        ei.e16,ei.e18,ei.e20,ei.e22,ei.e24,ei.e26 = \
        struct.unpack("<HHHHHHHhHHHhHH", tmpbytes)

    if ei.e0!=0x5a4d and ei.e0!=0x4d5a:
        return

    fctx.codepos = 16*ei.e8
    ei.num_relocs = ei.e6
    ei.reloc_pos = ei.e24
    ei.reloc_end = ei.reloc_pos + 4*ei.num_relocs

    detect_and_decode_ext_exe(ctx, fctx, ei)
    if ei.is_ext_exe:
        return

    decode_dos_exe(ctx, fctx, ei)
    if fctx.hash_strat!=2:
        fctx.hash_strat = 1
        fctx.codepos = 0
        fctx.codesize = fctx.filesize

def onefile(ctx, fn):
    fctx = file_context(ctx)
    if (len(fn)>2) and (fn[0:2]=='./'):
        fctx.name_friendly = fn[2:]
    else:
        fctx.name_friendly = fn

    try:
        fctx.inf = open(fn, "rb")
        fctx.isopen = True
    except OSError:
        fctx.msg = "CANT-READ"

    if fctx.isopen:
        fctx.inf.seek(0, 2)
        fctx.filesize = fctx.inf.tell()

        fctx.msg = 'OK' # default
        fctx.ffmt = 'MISC'
        fctx.hash_strat = 1 # default to whole file
        fctx.codepos = 0
        fctx.codesize = fctx.filesize

        detect_and_decode_exe(ctx, fctx)

        if fctx.codesize>0 and \
            (fctx.codepos+fctx.codesize <= fctx.filesize):
            fctx.inf.seek(fctx.codepos, 0)
            codeblob = bytearray(fctx.inf.read(fctx.codesize))
            fctx.hash = ctx.crcobj.oneshot(codeblob)
        else:
            fctx.hash_strat = 0
            fctx.codesize = 0

        fctx.inf.close()

        if fctx.hash in ctx.dict:
            fctx.file_id = ctx.dict[fctx.hash]
    else:
        fctx.hash_strat = 0

    if ctx.opt_uppercase:
        print('%08X' % (fctx.hash), end='')
    else:
        print('%08x' % (fctx.hash), end='')
    print(';csz=%d;fsz=%d;t=%s;m=%s;h=%s;id=%s|%s' % ( \
        fctx.codesize, fctx.filesize, \
        fctx.ffmt, fctx.msg, fctx.hash_strat, \
        fctx.file_id, fctx.name_friendly))

def read_dict_file(ctx, dict_fn):
    dict_inf = open(dict_fn, 'r', encoding='utf8', errors='replace')

    linenum = 0
    for line1 in dict_inf:
        linenum += 1
        line = line1.rstrip('\r\n')
        if (len(line)==0) or (line[0:1]=='#'):
            continue
        ss = line.split(sep='|')
        if len(ss)<2:
            raise Exception(f"Bad dictionary (line {linenum})")
        linenum += 1
        idstr = ss[-1] # Want everything after the last '|'
        crcstr = line[0:8]
        crcnum = int(crcstr, base=16)

        if (crcnum!=0) and not (crcnum in ctx.dict):
            ctx.dict[crcnum] = idstr

    dict_inf.close()

def usage():
    print("Exehash")
    print("Checksum the \"code image\" segment of an EXE file")
    print("Usage: exehash.py [options] file1 [file2...]")
    print("  Options:")
    print("   -d <dictfile> : Use a dictionary file")
    print("   -u : Print uppercase hex digits")

def main():
    ctx = context()
    input_filenames = []
    dict_filenames = []

    i = 1
    while i<len(sys.argv):
        if sys.argv[i][0]=='-':
            if sys.argv[i][1:]=='u':
                ctx.opt_uppercase = True
            elif sys.argv[i][1:]=='d':
                i += 1
                dict_filenames.append(sys.argv[i])
            else:
                print('Unrecognized option "%s"' % (sys.argv[i]))
                return
        else:
            input_filenames.append(sys.argv[i])
        i += 1

    if len(input_filenames)==0:
        usage()
        return

    ctx.crcobj = crc32_class(crc32_factory())

    for fn in dict_filenames:
        read_dict_file(ctx, fn)

    for fn in input_filenames:
        onefile(ctx, fn)

main()
