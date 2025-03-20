#!/usr/bin/python3

# exepacka.py
# Version 2025.??.??+
# by Jason Summers
#
# A script to parse an EXEPACK-compressed DOS EXE file, and
# print compression parameters.
#
# Terms of use: MIT license. See COPYING.txt.

import sys

crc32_tab = [
    0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
    0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
    0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
    0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c ]

def mycrc32(data):
    crc = 0
    crc = crc ^ 0xffffffff

    for i in range(len(data)):
        crc = (crc >> 4) ^ crc32_tab[(crc & 0xf) ^ (data[i] & 0xf)];
        crc = (crc >> 4) ^ crc32_tab[(crc & 0xf) ^ (data[i] >> 4)];

    crc = crc ^ 0xffffffff
    return crc

class ea_property:
    def __init__(self, dfltval):
        self.val_known = False
        self.val = dfltval
    def set(self, x):
        self.val = x
        self.val_known = True
    def is_true(self):
        if self.val_known and self.val:
            return True
        else:
            return False
    def is_false(self):
        if self.val_known and (not self.val):
            return True
        else:
            return False
    def is_true_or_unk(self):
        if (not self.val_known) or self.val:
            return True
        else:
            return False
    def is_false_or_unk(self):
        if (not self.val_known) or (not self.val):
            return True
        else:
            return False
    def getpr(self):
        if self.val_known:
            return self.val
        else:
            return '?'
    def getpr_hex(self):
        if self.val_known:
            return '0x%04x' % (self.val)
        else:
            return '?'
    def getpr_hex1(self):
        if self.val_known:
            return '0x%02x' % (self.val)
        else:
            return '?'
    def getpr_yesno(self):
        if self.val_known:
            if self.val:
                return 'yes'
            else:
                return 'no'
        else:
            return '?'
    def getpr_withrel(self, ctx):
        if self.val_known:
            # The "ctx.ip+" part prints the offset part of the likely load
            # address. Useful if using a disassembler.
            if not ctx.is_exe.val:
                return '%d (:%04x)' % (self.val, 0x0100+self.val)
            elif self.val >= ctx.entrypoint.val:
                rel_pos = self.val-ctx.entrypoint.val
                return '%d (e%+d, :%04x)' % (self.val, rel_pos, ctx.ip+rel_pos)
            else:
                return '%d (c%+d)' % (self.val, self.val-ctx.codestart.val)
        else:
            return '?'

class ea_bool(ea_property):
    def __init__(self):
        ea_property.__init__(self, False)

class ea_number(ea_property):
    def __init__(self):
        ea_property.__init__(self, 0)

class ea_string(ea_property):
    def __init__(self):
        ea_property.__init__(self, '?')

class ea_segment:
    def __init__(self):
        self.segclass = ea_string()
        self.pos = ea_number()

class global_context:
    def __init__(gctx):
        gctx.include_prefixes = False

class file_context:
    def __init__(ctx):
        ctx.errmsg = ''

        ctx.is_exe = ea_bool()
        ctx.is_exepack = ea_bool()
        ctx.executable_fmt = ea_string()

        ctx.file_size = ea_number()
        ctx.CS_pos_in_file = ea_number()
        ctx.entrypoint = ea_number()
        ctx.cs = 0
        ctx.ip = 0
        ctx.reloc_tbl_pos = 0
        ctx.reloc_tbl_end = 0
        ctx.codestart = ea_number()
        ctx.codeend = ea_number()
        ctx.epilogpos = ea_number()
        ctx.overlay = ea_segment()
        ctx.overlay_size = ea_number()
        ctx.decoder_size = ea_number()
        ctx.start_of_cmpr_data = ea_number()
        ctx.cmpr_data_len = ea_number()
        ctx.end_of_cmpr_data = ea_number()
        ctx.uncmpr_data_len = ea_number()
        ctx.createdby = ea_string()
        ctx.errmsg_pos = ea_number()
        ctx.crc_region_pos = ea_number()
        ctx.crc_region_len = ea_number()
        ctx.crc_fingerprint = ea_number()
        ctx.tags = []

        ctx.header_pos = ea_number()
        ctx.header_size = ea_number()
        ctx.decoder = ea_segment()

        ctx.cmpr_reloc_tbl_pos = ea_number()
        ctx.cmpr_reloc_tbl_size = ea_number()
        ctx.cmpr_reloc_tbl_nrelocs = ea_number()

        ctx.dest_len = 0
        ctx.skip_len = 0 # Meaningful if >1
        ctx.reported_exepack_size = 0

def getbyte(ctx, offset):
    if offset+1 > len(ctx.blob):
        raise Exception("Malformed file")
    return ctx.blob[offset]

def getu16(ctx, offset):
    if offset+2 > len(ctx.blob):
        raise Exception("Malformed file")
    val = ctx.blob[offset] + 256*ctx.blob[offset+1]
    return val

def gets16(ctx, offset):
    val = getu16(ctx, offset)
    if val >= 0x8000:
        val -= 0x10000
    return val

def ip_to_filepos(ctx, ip):
    return ctx.CS_pos_in_file.val + ip

def bseq_match(ctx, pos1, vals, wildcard):
    if pos1+len(vals) > len(ctx.blob):
        return False

    for i in range(len(vals)):
        if vals[i] == wildcard:
            continue
        if ctx.blob[pos1+i] != vals[i]:
            return False

    return True

def bseq_exact(ctx, pos1, vals):
    if pos1+len(vals) > len(ctx.blob):
        return False

    for i in range(len(vals)):
        if ctx.blob[pos1+i] != vals[i]:
            return False

    return True

# maxbytes is the number of starting positions to consider
# (not the size of the 'haystack').
def find_bseq_match(ctx, startpos, maxbytes, vals, wildcard):
    pos = startpos

    while pos < startpos+maxbytes:
        if pos+len(vals) > ctx.file_size.val:
            return False, 0

        foundmatch = True

        for i in range(len(vals)):
            if vals[i] == wildcard:
                continue
            if ctx.blob[pos+i] != vals[i]:
                foundmatch = False
                break

        if foundmatch:
            return True, pos

        pos += 1

    return False, 0

# maxbytes is the number of starting positions to consider
# (not the size of the 'haystack').
def find_bseq_exact(ctx, startpos, maxbytes, vals):
    pos = startpos

    while pos < startpos+maxbytes:
        if pos+len(vals) > ctx.file_size.val:
            return False, 0

        foundmatch = True

        for i in range(len(vals)):
            if ctx.blob[pos+i] != vals[i]:
                foundmatch = False
                break

        if foundmatch:
            return True, pos

        pos += 1

    return False, 0

def ea_open_file(ctx):
    inf = open(ctx.infilename, "rb")
    ctx.blob = bytearray(inf.read())
    inf.close()
    ctx.file_size.set(len(ctx.blob))

def ea_read_exe(ctx):
    ctx.executable_fmt.set('EXE')
    e_cblp = getu16(ctx, 2)
    e_cp = getu16(ctx, 4)

    num_relocs = getu16(ctx, 6)
    e_cparhdr = getu16(ctx, 8)
    ctx.codestart.set(e_cparhdr*16)

    if e_cblp==0:
        ctx.codeend.set(512 * e_cp)
    else:
        ctx.codeend.set(512 * (e_cp-1) + e_cblp)

    ctx.ip = getu16(ctx, 20)
    ctx.cs = gets16(ctx, 22)
    ctx.CS_pos_in_file.set(ctx.codestart.val + 16*ctx.cs)
    ctx.entrypoint.set(ctx.codestart.val + 16*ctx.cs + ctx.ip)

    ctx.reloc_tbl_pos = getu16(ctx, 24)
    ctx.reloc_tbl_end = ctx.reloc_tbl_pos + 4*num_relocs

    if ctx.codeend.val <= ctx.file_size.val:
        ctx.overlay_size.set(ctx.file_size.val - ctx.codeend.val)
    else:
        ctx.errmsg = "Truncated EXE file"
        return

    if ctx.overlay_size.val > 0:
        ctx.overlay.pos.set(ctx.codeend.val)

# Determine the file format, and read non-EXEPACK-specific data
def ea_read_main(ctx):
    ctx.is_exepack.set(False) # Default
    sig = getu16(ctx, 0)
    n = getbyte(ctx, 3)
    if (sig==0x5a4d or sig==0x4d5a) and (n<=1):
        ctx.is_exe.set(True)
        ea_read_exe(ctx)
    else:
        ctx.errmsg = "Not a supported file format"
        return

def ea_decode_overlay(ctx):
    if ctx.overlay_size.val < 1:
        return
    # (Reserved for future development.)

def ea_is_all_zeroes(ctx, pos1, pos2):
    if pos1 >= pos2:
        return True
    if pos2 > len(ctx.blob):
        return False
    for i in range(pos1, pos2):
        if ctx.blob[i] != 0x00:
            return False
    return True

def ea_check_cdata2(ctx):
    rte = ctx.reloc_tbl_end
    if rte < 28:
        rte = 28
    if not ea_is_all_zeroes(ctx, rte, ctx.codestart.val):
        ctx.tags.append('custom data after reloc table')

# Find and decode the 16-byte or 18-byte EXEPACK header.
# Set ctx.decoder.pos.
def ea_decode_header(ctx):
    if ctx.is_exe.is_false_or_unk():
        return

    pos = ctx.CS_pos_in_file.val

    if ctx.ip==16:
        if bseq_match(ctx, ctx.entrypoint.val-2, b'RB', 0x3f):
            ctx.header_pos.set(ctx.CS_pos_in_file.val)
            ctx.header_size.set(ctx.ip)
    elif ctx.ip==18:
        if bseq_match(ctx, ctx.entrypoint.val-2, b'RB', 0x3f):
            ctx.header_pos.set(ctx.CS_pos_in_file.val)
            ctx.header_size.set(ctx.ip)

    if ctx.header_pos.val_known:
        ctx.is_exepack.set(True)
        ctx.decoder.pos.set(ctx.entrypoint.val)
    else:
        ctx.errmsg = 'Unknown EXEPACK version, or not an EXEPACK-compressed file'

    if not ctx.header_pos.val_known:
        return

    ctx.reported_exepack_size = getu16(ctx, ctx.header_pos.val + 6)
    ctx.dest_len = getu16(ctx, ctx.header_pos.val + 12)
    if ctx.header_size.val==18:
        ctx.skip_len = getu16(ctx, ctx.header_pos.val + 14)

# Decode the main part of the EXEPACK decoder.
# Requires ctx.decoder.pos to be set.
def ea_decode_decoder(ctx):
    if not ctx.decoder.pos.val_known:
        return
    if not ctx.epilogpos.val_known:
        return
    if not ctx.crc_fingerprint.val_known:
        return

    found = False
    pos = ctx.decoder.pos.val
    pos_of_reloc_ptr = 0

    if (not found) and (ctx.crc_fingerprint.val==0x77dc4e4a):
        ctx.decoder_size.set(258)
        ctx.decoder.segclass.set("common258")
        ctx.createdby.set("EXEPACK 4.00, etc.")
        ctx.cmpr_reloc_tbl_pos.set(pos+ctx.decoder_size.val)
        found = True

    if (not found) and (ctx.crc_fingerprint.val==0x7b0bb610):
        ctx.decoder_size.set(277)
        ctx.decoder.segclass.set("common277")
        ctx.createdby.set("LINK 3.60/etc.")
        ctx.cmpr_reloc_tbl_pos.set(pos+ctx.decoder_size.val)
        found = True

    if (not found) and (ctx.crc_fingerprint.val==0xae58e006):
        ctx.decoder_size.set(279)
        ctx.decoder.segclass.set("common279")
        ctx.createdby.set("EXEPACK 4.03, etc.")
        ctx.cmpr_reloc_tbl_pos.set(pos+ctx.decoder_size.val)
        found = True

    if (not found) and (ctx.crc_fingerprint.val==0xa6a446ac):
        ctx.decoder_size.set(283)
        ctx.decoder.segclass.set("common283")
        ctx.createdby.set("EXEPACK 4.05-4.06")
        ctx.cmpr_reloc_tbl_pos.set(pos+ctx.decoder_size.val)
        found = True

    if (not found) and (ctx.crc_fingerprint.val==0x7755de74):
        ctx.decoder_size.set(283)
        ctx.decoder.segclass.set("WordPerfect283")
        ctx.cmpr_reloc_tbl_pos.set(pos+ctx.decoder_size.val)
        found = True

    if (not found) and (ctx.crc_fingerprint.val==0x1797940c):
        ctx.decoder_size.set(290)
        ctx.decoder.segclass.set("common290")
        ctx.createdby.set("LINK 5.60/etc.")
        ctx.cmpr_reloc_tbl_pos.set(pos+ctx.decoder_size.val)
        found = True

    if (not found) and (ctx.crc_fingerprint.val==0xb3e99388):
        ctx.decoder_size.set(290)
        ctx.decoder.segclass.set("DECOMP")
        ctx.cmpr_reloc_tbl_pos.set(pos+ctx.decoder_size.val)
        found = True

    if (not found) and (ctx.crc_fingerprint.val==0xce1bf069):
        ctx.decoder_size.set(291)
        ctx.decoder.segclass.set("Artisoft291")
        ctx.cmpr_reloc_tbl_pos.set(pos+ctx.decoder_size.val)
        found = True

    if (not found) and (ctx.crc_fingerprint.val==0xc705ff4f):
        ctx.decoder_size.set(258)
        ctx.decoder.segclass.set("EXEPATCK258")
        ctx.createdby.set("EXEPATCK")
        ctx.cmpr_reloc_tbl_pos.set(pos+ctx.decoder_size.val)
        found = True

    if (not found) and (ctx.crc_fingerprint.val==0x87ba64ac):
        ctx.decoder_size.set(277)
        ctx.decoder.segclass.set("EXEPATCK277")
        ctx.createdby.set("EXEPATCK")
        ctx.cmpr_reloc_tbl_pos.set(pos+ctx.decoder_size.val)
        found = True

    if (not found) and (ctx.crc_fingerprint.val==0x10417761):
        ctx.decoder_size.set(279)
        ctx.decoder.segclass.set("EXEPATCK279")
        ctx.createdby.set("EXEPATCK")
        ctx.cmpr_reloc_tbl_pos.set(pos+ctx.decoder_size.val)
        found = True

    if (not found) and (ctx.crc_fingerprint.val==0x5a159410):
        ctx.decoder_size.set(283)
        ctx.decoder.segclass.set("EXEPATCK283")
        ctx.createdby.set("EXEPATCK")
        ctx.cmpr_reloc_tbl_pos.set(pos+ctx.decoder_size.val)
        found = True

    if (not found) and (ctx.crc_fingerprint.val==0x4745c5ca):
        ctx.decoder_size.set(283)
        ctx.decoder.segclass.set("LOWFIX")
        ctx.createdby.set("LOWFIX")
        ctx.cmpr_reloc_tbl_pos.set(pos+ctx.decoder_size.val)
        found = True

    if (not found) and (ctx.crc_fingerprint.val==0x848c6688):
        ctx.decoder_size.set(283)
        ctx.decoder.segclass.set("Fifield")
        ctx.createdby.set("D. Fifield's exepack")
        ctx.cmpr_reloc_tbl_pos.set(pos+ctx.decoder_size.val)
        found = True

    if not found:
        ok, foundpos = find_bseq_exact(ctx, pos+50, 120,
        b'\x0e\x1f\x8b\x1e\x04\x00\xfc\x33\xd2\xad')
        if ok:
            pos_of_reloc_ptr = foundpos-2
            found = True

    if not found:
        ok, foundpos = find_bseq_exact(ctx, pos+50, 120,
        b'\x0e\x1f\xfc\x8b\xd3\xad\x91\xe3\x14\xad')
        if ok:
            # TODO: Decide how to classify these decoders.
            #ctx.decoder.segclass.set("EXPAKFIX")
            ctx.createdby.set("EXPAKFIX")
            pos_of_reloc_ptr = foundpos-2
            found = True

    if found and (pos_of_reloc_ptr>0):
        ctx.cmpr_reloc_tbl_pos.set(ip_to_filepos(ctx, \
            getu16(ctx, pos_of_reloc_ptr)))

# * Find the epilog.
# * Calculate the decoder fingerprint.
def ea_decode_epilog(ctx):
    if not ctx.entrypoint.val_known:
        return

    found = False
    pos = ctx.entrypoint.val

    # search for epilog
    ok, foundpos = find_bseq_exact(ctx, pos+180, 180,
        b'\xCD\x21\xB8\xFF\x4C\xCD\x21')

    if ok and (foundpos-ctx.entrypoint.val < 50):
        ok = False

    if not ok:
        ctx.errmsg = "Can't find epilog"
        return

    region_endpos = foundpos - 15

    ctx.epilogpos.set(foundpos)

    ctx.crc_region_pos.set(ctx.entrypoint.val)
    ctx.crc_region_len.set(region_endpos-ctx.entrypoint.val)
    ctx.crc_fingerprint.set(mycrc32(ctx.blob[ctx.crc_region_pos.val : \
        region_endpos]))

def ea_find_num_relocs(ctx):
    if not ctx.cmpr_reloc_tbl_pos.val_known:
        return
    if not ctx.cmpr_reloc_tbl_size.val_known:
        return

    # It's easy to deduce the number of relocations, without decompressing.
    if ctx.cmpr_reloc_tbl_size.val < 32:
        return
    n = (ctx.cmpr_reloc_tbl_size.val - 32) // 2
    ctx.cmpr_reloc_tbl_nrelocs.set(n)

def ea_deduce_settings1(ctx):
    if (not ctx.errmsg_pos.val_known) and \
        ctx.epilogpos.val_known:
        errmsg_pos_ptr = getu16(ctx, ctx.epilogpos.val-2)
        ctx.errmsg_pos.set(ctx.CS_pos_in_file.val + \
            errmsg_pos_ptr)

    if (not ctx.cmpr_reloc_tbl_pos.val_known) and \
        (not ctx.decoder_size.val_known) and \
        ctx.epilogpos.val_known:
        ctx.cmpr_reloc_tbl_pos.set(ctx.epilogpos.val + 7 + 22)

    if ctx.decoder.pos.val_known and ctx.cmpr_reloc_tbl_pos.val_known:
        ctx.decoder_size.set(ctx.cmpr_reloc_tbl_pos.val - ctx.decoder.pos.val)

    if (not ctx.cmpr_reloc_tbl_pos.val_known) and \
        ctx.decoder.pos.val_known and ctx.decoder_size.val_known:
        ctx.cmpr_reloc_tbl_pos.set(ctx.decoder.pos.val + ctx.decoder_size.val)

    ctx.start_of_cmpr_data.set(ctx.codestart.val)

    if ctx.skip_len>1:
        tmp_skip_len = ctx.skip_len
    else:
        tmp_skip_len = 1

    ctx.cmpr_data_len.set(16*(ctx.cs - tmp_skip_len + 1))
    ctx.end_of_cmpr_data.set(ctx.start_of_cmpr_data.val + \
        ctx.cmpr_data_len.val)
    ctx.uncmpr_data_len.set(16*(ctx.dest_len - tmp_skip_len + 1))
    if ctx.cmpr_reloc_tbl_pos.val_known:
        ctx.cmpr_reloc_tbl_size.set(ctx.CS_pos_in_file.val + \
        ctx.reported_exepack_size - ctx.cmpr_reloc_tbl_pos.val)
        ea_find_num_relocs(ctx)

def ea_check_errmsg(ctx):
    if not ctx.errmsg_pos.val_known:
        return

    ok = bseq_exact(ctx, ctx.errmsg_pos.val, \
        b'Packed file is corrupt')

    if not ok:
        ctx.tags.append('modified error message')

def report_exe_specific(ctx):
    print(ctx.p_INFO+'host code start:', ctx.codestart.getpr())
    print(ctx.p_INFO+'host code end:', ctx.codeend.getpr())
    # Could print these things, but it's redundant.
    #print(ctx.p_INFO+'CS:', ctx.CS_pos_in_file.getpr_withrel(ctx))
    #print(ctx.p_INFO+'initial IP (relative to CS):', ctx.ip)
    print(ctx.p_INFO+'host entry point:', ctx.entrypoint.getpr())

    print(ctx.p_MED+'host reloc tbl pos:', ctx.reloc_tbl_pos)

    has_overlay = ea_bool()
    if ctx.overlay_size.val > 0:
        has_overlay.set(True)
    else:
        has_overlay.set(False)

    print(ctx.p_MED+'host has overlay:', has_overlay.getpr_yesno())
    if ctx.overlay_size.val > 0:
        print(ctx.p_MED+' overlay pos:', ctx.overlay.pos.getpr())
        print(ctx.p_MED+' overlay size:', ctx.overlay_size.getpr())
        # Suppressed, due to lack of interesting identifiable overlay
        # formats that I know of.
        # print(ctx.p_LOW+' overlay class:', ctx.overlay.segclass.getpr())

def report_exepack_specific(ctx):
    print(ctx.p_HIGH+'EXEPACK header pos:', ctx.header_pos.getpr_withrel(ctx))
    print(ctx.p_INFO+' EXEPACK header size:', ctx.header_size.getpr())
    if ctx.header_size.val==18:
        print(ctx.p_INFO+' skip len:', ctx.skip_len)

    # (The importance of this field is elevated, because the decompression
    # is done backwards.)
    print(ctx.p_HIGH+' uncmpr data len:', ctx.uncmpr_data_len.getpr())

    print(ctx.p_CRIT+'cmpr data pos:', ctx.start_of_cmpr_data.getpr_withrel(ctx))
    print(ctx.p_INFO+' cmpr data len:', ctx.cmpr_data_len.getpr())
    print(ctx.p_CRIT+' cmpr data end:', ctx.end_of_cmpr_data.getpr_withrel(ctx))

    print(ctx.p_INFO+'decoder pos:', ctx.decoder.pos.getpr_withrel(ctx))
    print(ctx.p_INFO+' decoder size:', ctx.decoder_size.getpr())
    print(ctx.p_INFO+' decoder epilog pos:', ctx.epilogpos.getpr_withrel(ctx))

    print(ctx.p_INFO+' decoder fingerprint region pos:', \
        ctx.crc_region_pos.getpr_withrel(ctx))
    print(ctx.p_INFO+' decoder fingerprint region len:', ctx.crc_region_len.val)

    print(ctx.p_INFO+' decoder fingerprint: 0x%08x' % (ctx.crc_fingerprint.val))

    print(ctx.p_INFO+' decoder class:', ctx.decoder.segclass.val)

    print(ctx.p_INFO+' error message pos:', ctx.errmsg_pos.getpr_withrel(ctx))

    print(ctx.p_HIGH+'cmpr reloc tbl pos:', ctx.cmpr_reloc_tbl_pos.getpr_withrel(ctx))
    print(ctx.p_LOW+' cmpr reloc tbl size:', ctx.cmpr_reloc_tbl_size.getpr())
    if ctx.cmpr_reloc_tbl_size.val_known:
        print(ctx.p_INFO+' cmpr reloc tbl num relocs:', \
            ctx.cmpr_reloc_tbl_nrelocs.getpr())

    print(ctx.p_INFO+'created by:', ctx.createdby.getpr())
    if len(ctx.tags) > 0:
        print(ctx.p_LOW+'tags: [', end='')
        print('] ['.join(ctx.tags), end='')
        print(']')

def ea_report(ctx):
    if ctx.include_prefixes:
        ctx.p_INFO = 'INFO: ' # Not needed.
        ctx.p_LOW  = 'LOW : ' # Might have *some* use.
        ctx.p_MED  = 'MED : ' # Useful for best results.
        ctx.p_HIGH = 'HIGH: ' # Needed to decompress to a runnable file.
        ctx.p_CRIT = 'CRIT: ' # Needed to decompress the code image.
    else:
        ctx.p_INFO = ''
        ctx.p_LOW  = ''
        ctx.p_MED  = ''
        ctx.p_HIGH = ''
        ctx.p_CRIT = ''

    print(ctx.p_INFO+'file size:', ctx.file_size.getpr())

    print(ctx.p_CRIT+'executable format:', ctx.executable_fmt.getpr())
    print(ctx.p_CRIT+'EXEPACK detected:', ctx.is_exepack.getpr_yesno())

    if ctx.is_exe.is_true():
        report_exe_specific(ctx)
    if ctx.is_exepack.is_true():
        report_exepack_specific(ctx)

def usage():
    print('usage: exepacka.py [options] <infile>')
    print(' options: -p  Print item importance')

def main_onefile(gctx, filename):
    ctx = file_context()
    ctx.include_prefixes = gctx.include_prefixes
    ctx.infilename = filename

    print('file:', ctx.infilename)
    ea_open_file(ctx)
    if ctx.errmsg=='':
        ea_read_main(ctx)
    if ctx.errmsg=='':
        ea_decode_overlay(ctx)
    if ctx.errmsg=='':
        ea_check_cdata2(ctx)
    if ctx.errmsg=='':
        ea_decode_header(ctx)
    if ctx.errmsg=='':
        ea_decode_epilog(ctx)
    if ctx.errmsg=='':
        ea_decode_decoder(ctx)

    ea_deduce_settings1(ctx)

    if ctx.errmsg=='':
        ea_check_errmsg(ctx)
    ea_report(ctx)
    if ctx.errmsg!='':
        print('Error:', ctx.errmsg)

def main():
    gctx = global_context()
    xcount = 0
    for i in range(1, len(sys.argv)):
        arg = sys.argv[i]
        if arg[0:1]=='-':
            if arg=='-p':
                gctx.include_prefixes = True
            continue
        xcount += 1

    if xcount!=1:
        usage()
        return

    # Currently, we only support one file, but that may change at
    # some point.
    for i in range(1, len(sys.argv)):
        if sys.argv[i][0]!='-':
            main_onefile(gctx, sys.argv[i])

main()
