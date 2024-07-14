#!/usr/bin/python3
#
# rqlpng.py - Uncompressed PNG Maker Demo
# (Previously named uncpngmaker.py)
# 2023-11-27 - 2024-07-15
# Copyright (C) 2023-2024 by Jason Summers
#
# Terms of use: MIT license.
#
# A script to create an "uncompressed" PNG image file.
#
# Works by using Deflate's non-compressed block type.
#
# Supported input formats:
# - 24-bit BMP
# - Farbfeld
#
# More info: https://entropymine.wordpress.com/2023/11/28/making-an-uncompressed-png-image-file/

import sys

class rawimage:
    def __init__(im):
        im.bit_depth = 8
        im.rawdata = bytearray()

class pngchunk:
    def __init__(ch):
        ch.chunktype = bytearray()
        ch.chunkdata = bytearray()

class context:
    def __init__(ctx):
        ctx.max_width = 16383
        ctx.max_height = 16383
        ctx.crc = 0
        ctx.adler32_s1 = 1
        ctx.adler32_s2 = 0

crc32_tab = [
    0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
    0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
    0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
    0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c ]

# To reset: "ctx.crc = 0"
def crc32_update(ctx, data):
    crc = ctx.crc ^ 0xffffffff

    for i in range(len(data)):
        crc = (crc >> 4) ^ crc32_tab[(crc & 0xf) ^ (data[i] & 0xf)];
        crc = (crc >> 4) ^ crc32_tab[(crc & 0xf) ^ (data[i] >> 4)];

    ctx.crc = crc ^ 0xffffffff

# To reset: ctx.adler32_s1 = 1; ctx.adler32_s2 = 0
def adler32_update(ctx, data):
    for i in range(len(data)):
        ctx.adler32_s1 = (ctx.adler32_s1 + data[i]) % 65521
        ctx.adler32_s2 = (ctx.adler32_s2 + ctx.adler32_s1) % 65521

def write_pngchunk(ctx, ch):
    ctx.outf.write(len(ch.chunkdata).to_bytes(4, byteorder='big'))
    ctx.outf.write(ch.chunktype)
    ctx.outf.write(ch.chunkdata)
    ctx.crc = 0
    crc32_update(ctx, ch.chunktype)
    crc32_update(ctx, ch.chunkdata)
    ctx.outf.write(ctx.crc.to_bytes(4, byteorder='big'))

def upng_write_one_segment(ctx, img, first_row, num_rows):
    ch = pngchunk()
    ch.chunktype.extend(b'IDAT')

    is_last_segment = (first_row+num_rows >= img.height)

    # Deflate block header (common part)
    # The common part of the block header is just 3 bits in size,
    # but because byte alignment is forced both before
    # and after, it is effectively 1 whole byte.
    if is_last_segment:
        ch.chunkdata.append(0x01)
    else:
        ch.chunkdata.append(0x00)

    # Deflate block header (the part specific to uncompressed blocks)
    blkdatasize = (1 + img.rowspan) * num_rows
    ccheck = blkdatasize ^ 0xffff
    ch.chunkdata.extend(blkdatasize.to_bytes(2, byteorder='little'))
    ch.chunkdata.extend(ccheck.to_bytes(2, byteorder='little'))

    checksum_startpos = len(ch.chunkdata)

    for j in range(first_row, first_row+num_rows):
        # Write a byte for the filter method for this row
        ch.chunkdata.append(0)
        # Copy one row
        ch.chunkdata.extend(img.rawdata[j*img.rowspan : \
            (j+1)*img.rowspan])

    # The Adler32 checksum is of the uncompressed data, after PNG
    # serialization and filtering, but before Deflate compression.
    # We don't really ever put the data into that format, so it's
    # not obvious where the checksum calculation should happen.
    # But since we're not doing compression, it's easy enough to just
    # read it back from the "compressed" data buffer.
    adler32_update(ctx, ch.chunkdata[checksum_startpos : len(ch.chunkdata)])

    write_pngchunk(ctx, ch)

def upng_write_IDAT_segments(ctx, img):
    max_rows_per_segment = 65535 // (1 + img.rowspan)

    if max_rows_per_segment < 1:
        raise Exception("Internal error")

    # zlib header gets its own IDAT chunk
    ch = pngchunk()
    ch.chunktype.extend(b'IDAT')
    ch.chunkdata.extend(b'\x78\x01')
    write_pngchunk(ctx, ch)

    cur_row = 0
    while cur_row < img.height:
        if cur_row + max_rows_per_segment > img.height:
            num_rows_this_segment = img.height - cur_row
        else:
            num_rows_this_segment = max_rows_per_segment

        upng_write_one_segment(ctx, img, cur_row, num_rows_this_segment)
        cur_row = cur_row + num_rows_this_segment

    # zlib trailer gets its own IDAT chunk
    ch = pngchunk()
    ch.chunktype.extend(b'IDAT')
    ch.chunkdata.extend(ctx.adler32_s2.to_bytes(2, byteorder='big'))
    ch.chunkdata.extend(ctx.adler32_s1.to_bytes(2, byteorder='big'))
    write_pngchunk(ctx, ch)

def upng_write_png(ctx, img):
    ctx.outf = open(ctx.outfilename, "wb")
    ctx.outf.write(b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a')

    # IHDR
    ch = pngchunk()
    ch.chunktype.extend(b'IHDR')
    ch.chunkdata.extend(img.width.to_bytes(4, byteorder='big'))
    ch.chunkdata.extend(img.height.to_bytes(4, byteorder='big'))
    ch.chunkdata.append(img.bit_depth)
    ch.chunkdata.append(img.color_type)
    ch.chunkdata.extend(b'\x00\x00\x00')
    write_pngchunk(ctx, ch)

    # tEXt
    ch = pngchunk()
    ch.chunktype.extend(b'tEXt')
    ch.chunkdata.extend(b'Software\x00')
    ch.chunkdata.extend(b'Uncompressed PNG Maker (RQLPNG)')
    write_pngchunk(ctx, ch)

    # IDAT...
    upng_write_IDAT_segments(ctx, img)

    # IEND
    ch = pngchunk()
    ch.chunktype.extend(b'IEND')
    write_pngchunk(ctx, ch)

    ctx.outf.close()

def check_dimensions(ctx, img):
    if img.width<1 or img.height<1 or \
        img.width>ctx.max_width or img.height>ctx.max_height:
        raise Exception("Unsupported image dimensions")

def upng_read_bmp(ctx, inf, ffhdr, img):
    bits_pos = int.from_bytes(ffhdr[10:14], byteorder='little')
    ihdr_size = int.from_bytes(ffhdr[14:18], byteorder='little')
    if ihdr_size<40:
        raise Exception("Unsupported BMP version")

    img.width = int.from_bytes(ffhdr[18:22], byteorder='little', \
        signed=True)
    img.height = int.from_bytes(ffhdr[22:26], byteorder='little', \
        signed=True)
    check_dimensions(ctx, img)

    bitcount = int.from_bytes(ffhdr[28:30], byteorder='little')
    if bitcount != 24:
        raise Exception("Unsupported BMP bit count")

    compression = int.from_bytes(ffhdr[30:34], byteorder='little')
    if compression != 0:
        raise Exception("Unsupported BMP compression")

    img.color_type = 2 # = RGB
    img.rowspan = img.width*3
    bmp_rowspan = ((img.width*bitcount + 31) // 32) * 4

    for j in range(img.height):
        inf.seek(bits_pos + bmp_rowspan*(img.height-1-j))
        rawrow = inf.read(bmp_rowspan)
        if len(rawrow) != bmp_rowspan:
            raise Exception("Bad input file")

        # Convert each pixel from BGR to RGB
        for k in range(img.width):
            img.rawdata.extend(bytes([rawrow[k*3+2],
                rawrow[k*3+1], rawrow[k*3]]))

def upng_read_ff(ctx, inf, ffhdr, img):
    img.width = int.from_bytes(ffhdr[8:12], byteorder='big')
    img.height = int.from_bytes(ffhdr[12:16], byteorder='big')
    check_dimensions(ctx, img)
    img.rowspan = img.width*4
    img.color_type = 6 # RGBA

    ff_rowspan = img.width*8

    inf.seek(16)
    for j in range(img.height):
        # Read a row
        rawrow = inf.read(ff_rowspan)
        if len(rawrow) != ff_rowspan:
            raise Exception("Bad input file")

        # Truncate each sample from 2 bytes to 1 byte
        for k in range(img.width*4):
            img.rawdata.append(rawrow[k*2])

def upng_run(ctx):
    if ctx.infilename == ctx.outfilename:
        raise Exception("Filenames can't be the same")
    img = rawimage()

    inf = open(ctx.infilename, "rb")
    try:
        ffhdr = inf.read(34)
        if ffhdr[0:8] == b'farbfeld':
            upng_read_ff(ctx, inf, ffhdr, img)
        elif ffhdr[0:2] == b'BM':
            upng_read_bmp(ctx, inf, ffhdr, img)
        else:
            raise Exception("Input file not in a supported format")
    finally:
        inf.close()

    upng_write_png(ctx, img)

def usage():
    print('usage: rqlpng.py <infile> <outfile.png>')

def main():
    ctx = context()

    xcount = 0
    for a1 in range(1, len(sys.argv)):
        arg = sys.argv[a1]
        if arg[0:1]=='-':
            continue
        xcount += 1
        if xcount==1:
            ctx.infilename = arg
        elif xcount==2:
            ctx.outfilename = arg

    if xcount!=2:
        usage()
        return

    upng_run(ctx)

main()
