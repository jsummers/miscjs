#!/usr/bin/env python3
#
# Mkbgb_j
# A script to create a Comic Chat BGB file from a BMP file.
# Copyright (C) 2025 Jason Summers
# https://github.com/jsummers/miscjs -> mkbgb_j
# Terms of use: MIT license. See COPYING.txt.
#
# Approximate version: 1.00, 2025-04-26

import sys
import zlib

CHKTYPE_PALETTE     = 0x0101
CHKTYPE_BGIMAGE     = 0x0102
CHKTYPE_COPYRIGHT   = 0x0103
CHKTYPE_URL         = 0x0104
CHKTYPE_DLPROT      = 0x0106

# Numbers here are arbitrary. Only the order matters.
CHKORDER_COPYRIGHT  = 30
CHKORDER_URL        = 40
CHKORDER_DLPROT     = 60
CHKORDER_BGIMAGE    = 80

class chunk:
    def __init__(ch):
        ch.chunkdata = bytearray()

class context:
    def __init__(ctx):
        ctx.chunks = {}
        ctx.copyright = ''
        ctx.author = ''
        ctx.url = ''
        ctx.dlprot = False
        ctx.bgb_encoding = 'cp1252'

def make_bgimage_chunk(ctx, ptr_to_image):
    ch = chunk()
    ch.chunktype = CHKTYPE_BGIMAGE

    ch.chunkdata.extend(ptr_to_image.to_bytes(4, byteorder='little'))
    # I don't know what this is, but it's always 01 02
    ch.chunkdata.extend(bytes.fromhex("01 02"))

    ctx.chunks[CHKORDER_BGIMAGE] = ch

def mkbgb_make_chunks(ctx):
    # This is a placeholder. It will be rewritten later.
    make_bgimage_chunk(ctx, 0)

    # Copyright/author
    ch = chunk()
    ch.chunktype = CHKTYPE_COPYRIGHT
    encstr1 = bytes(ctx.copyright, ctx.bgb_encoding)
    encstr2 = bytes(ctx.author, ctx.bgb_encoding)
    ch.chunkdata.extend(encstr1)
    if len(encstr2)>0:
        # Separator is a literal backslash n, not a newline.
        ch.chunkdata.extend(b"\\n")
        ch.chunkdata.extend(encstr2)
    # String chunks end with an unnecessary NUL byte
    ch.chunkdata.append(0x00)
    ctx.chunks[CHKORDER_COPYRIGHT] = ch

    if ctx.url:
        ch = chunk()
        ch.chunktype = CHKTYPE_URL
        encstr1 = bytes(ctx.url, 'ascii')
        ch.chunkdata.extend(encstr1)
        ch.chunkdata.append(0x00)
        ctx.chunks[CHKORDER_URL] = ch

    if ctx.dlprot:
        ch = chunk()
        ch.chunktype = CHKTYPE_DLPROT
        ch.chunkdata.append(0x01)
        ctx.chunks[CHKORDER_DLPROT] = ch

    # Calculate the position of the data segment
    chunks_tot_len = 0
    for key in list(ctx.chunks):
        chunks_tot_len += 4 + len(ctx.chunks[key].chunkdata)

    # --------------
    # Now that we know where the data segment will be,
    # rewrite the chunk(s) that depend on it.

    # 6 for file header, 2 for the 06 00 marker.
    make_bgimage_chunk(ctx, 6+chunks_tot_len+2)

def write_chunk(ctx, ch, outf):
    outf.write(ch.chunktype.to_bytes(2, byteorder='little'))
    outf.write(len(ch.chunkdata).to_bytes(2, byteorder='little'))
    outf.write(ch.chunkdata)

def mkbgb_write_bgb(ctx, outf):
    # File header
    outf.write(bytes.fromhex('81 81 03 00 02 00'))

    # Main sequence of chunks
    for key in sorted(ctx.chunks):
        ch = ctx.chunks[key]
        write_chunk(ctx, ch, outf)

    # Marker: Start of data section
    outf.write(bytes.fromhex('06 00'))

    # Palette
    write_chunk(ctx, ctx.pal_ch, outf)

    # BMP Infoheader
    outf.write(ctx.bmpblob[14:(14+ctx.bmp_ihdr_size)])

    # Header for compressed part
    orig_len = ctx.bmp_bits_size
    cmpr_len = len(ctx.cmpr_image)
    outf.write(orig_len.to_bytes(4, byteorder='little'))
    outf.write(cmpr_len.to_bytes(4, byteorder='little'))

    # Compressed image data
    outf.write(ctx.cmpr_image)

    # Marker: End of data section
    outf.write(bytes.fromhex('07 00'))

def mkbgb_process_bmp(ctx):
    b = ctx.bmpblob

    if b[0]!=0x42 or b[1]!=0x4d:
        raise Exception("Not a BMP file")
    bmp_bfSize = int.from_bytes(b[2:6], byteorder='little')
    bmp_bfOffBits = int.from_bytes(b[10:14], byteorder='little')
    ctx.bmp_ihdr_size = int.from_bytes(b[14:18], byteorder='little')
    bmp_bitcount = int.from_bytes(b[28:30], byteorder='little')
    bmp_compression = int.from_bytes(b[30:34], byteorder='little')
    bmp_biSizeImage = int.from_bytes(b[34:38], byteorder='little')
    bmp_numcolors = int.from_bytes(b[46:50], byteorder='little')

    if ctx.bmp_ihdr_size!=40:
        raise Exception("Unsuitable BMP version")

    if bmp_bitcount!=1 and bmp_bitcount!=4 and bmp_bitcount!=8 and \
        bmp_bitcount!=24:
        raise Exception("Unsuitable BMP bit count")
        # TODO: Other bitcounts might be valid, but I don't know.

    if bmp_compression!=0:
        raise Exception("Unsuitable BMP file (compressed)")

    if bmp_bitcount<=8 and bmp_numcolors==0:
        bmp_numcolors = 1<<bmp_bitcount

    if bmp_bitcount>8 and bmp_numcolors!=0:
        raise Exception("Unsuitable BMP (RGB w/palette)")

    expected_bfOffBits = 14 + ctx.bmp_ihdr_size + 4*bmp_numcolors
    if bmp_bfOffBits!=expected_bfOffBits:
        raise Exception("Unsuitable BMP (has a gap)")

    if bmp_biSizeImage!=0:
        ctx.bmp_bits_size = bmp_biSizeImage
    elif bmp_bfSize!=0:
        ctx.bmp_bits_size = bmp_bfSize - bmp_bfOffBits
    else:
        ctx.bmp_bits_size = len(b) - bmp_bfOffBits

    # Convert the palette to chunk format
    ctx.pal_ch = chunk()
    ctx.pal_ch.chunktype = CHKTYPE_PALETTE
    ctx.pal_ch.chunkdata.extend(bmp_numcolors.to_bytes(2, byteorder='little'))
    # Colors are converted from BGRx to RGB
    palpos = 14+ctx.bmp_ihdr_size
    for k in range(bmp_numcolors):
        ctx.pal_ch.chunkdata.append(b[palpos+k*4+2]);
        ctx.pal_ch.chunkdata.append(b[palpos+k*4+1]);
        ctx.pal_ch.chunkdata.append(b[palpos+k*4+0]);

    # Compress the image data
    ctx.cmpr_image = zlib.compress( \
        b[bmp_bfOffBits:(bmp_bfOffBits+ctx.bmp_bits_size)], \
        level=9)
    print('[compressed %d to %d bytes]' % (ctx.bmp_bits_size, \
        len(ctx.cmpr_image)))

def mkbgb_run(ctx):
    if ctx.bmp_filename == ctx.bgb_filename:
        raise Exception("Filenames must be different")

    print(f'[reading and processing {ctx.bmp_filename}]')
    inf = open(ctx.bmp_filename, "rb")
    ctx.bmpblob = bytearray(inf.read())
    inf.close()
    mkbgb_process_bmp(ctx)

    print('[constructing BGB file]')
    mkbgb_make_chunks(ctx)

    print(f'[writing {ctx.bgb_filename}]')
    outf = open(ctx.bgb_filename, "wb")
    mkbgb_write_bgb(ctx, outf)
    outf.close()

def usage():
    print('Usage: mkbgb_j.py <infile.bmp> <outfile.bgb> [options]')
    print(' Options:')
    print('  -c "<copyright>"')
    print('  -a "<author>"')
    print('  -u "<URL>"')
    print('  -p            : Mark as download protected')
    print('  -e <encoding> : Character encoding of BGB file')

def main():
    ctx = context()
    print('mkbgb_j: BMP to BGB (MS Comic Chat background) converter')

    errflag = False
    fncount = 0
    n = 1
    while n < len(sys.argv):
        arg = sys.argv[n]

        if arg=='-a':
            ctx.author = sys.argv[n+1]
            n += 2
            continue
        if arg=='-c':
            ctx.copyright = sys.argv[n+1]
            n += 2
            continue
        if arg=='-u':
            ctx.url = sys.argv[n+1]
            n += 2
            continue
        if arg=='-e':
            ctx.bgb_encoding = sys.argv[n+1]
            n += 2
            continue
        if arg=='-p':
            ctx.dlprot = True
            n += 1
            continue
        if arg[0:1]=='-':
            errflag = True
            break

        if fncount==0:
            ctx.bmp_filename = arg
        elif fncount==1:
            ctx.bgb_filename = arg
        else:
            errflag = True
            break
        fncount += 1
        n += 1

    if (fncount!=2) or errflag:
        usage()
        return

    mkbgb_run(ctx)

main()
