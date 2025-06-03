Exehash

A simple fingerprinting utility for DOS EXE files
Copyright (C) 2025 Jason Summers
Terms of use: MIT license. See COPYING.txt.

Exehash is a Python script. It fingerprints (hashes) only the "code
segment" of DOS EXE files, to try to make the fingerprint robust against
certain kinds of insignificant modification.

For example, if an EXE file were to be compressed using "executable
compression" (such as LZEXE), then decompressed, the resulting file would
probably not be exactly the same as the original. But its Exahash
fingerprint would probably be the same.

For a list of options, run the script without parameters.

Caution: Exehash is expected to be used on the EXE file that you would
run to *run* the software, not on a "self-extracting" EXE file that you
might run to *install* the software. In many cases, the payload of a
self-extracting EXE file will be invisible to Exehash.

Formats other than DOS EXE are tolerated, because why not, but usually
the hash is simply computed on the entire file. For extended EXE formats
such as PE, the first 60 bytes are ignored, which is (slightly) better
than nothing.

With the -d option, you can supply a "dictionary" file, to give names to
known fingerprints. If there is a match, it will appear in the "id" field
of the output. "-d" can be used multiple times, for multiple dictionary
files.

What's the use? Suppose you want to find all the versions of piece of DOS
software. You could download their EXE files from DiscMaster
(https://discmaster.textfiles.com/), then use Exehash to help filter out
duplicates, and to help remember what's what.

------------ Output format

Here's an example of using Exehash:

$ exehash.py LHARC.EXE
73bd5158;csz=30744;fsz=31256;t=EXE-DOS;m=OK;h=2;id=UNK|LHARC.EXE

The first 8 characters are the hash (CRC-32 IEEE).
csz is the size in bytes of the code segment, or the part of the file for
which the hash was computed.
fsz is the size in bytes of the whole file.
t is the file format or type. EXE-DOS is the main supported format, but a
few others may be recognized or handled specially.
m is a short status message: either "OK", or some sort of error.
h is the hashing strategy that was used:
  0=None
  1=Whole file
  2=DOS EXE strategy
  3=Other EXE strategy
id is always "UNK" unless the dictionary feature was used.
Everything after the "|" is the input filename, for reference.

------------ Dictionary file format

The first 8 characters of a line are the hash. Everything after the last
"|" character is the identifier. Everything else is insignificant. The output
of Exehash can be used as a dictionary file.
