MHD (mhd.py) is a Python script that does a one-line hex dump of multiple
files. It can be used as a quick way to compare many files, to see some of
their similarities and differences.

For license and copyright information, see the comments at the beginning of
the file.

For instructions, run the script with no parameters.

Additional information:

Options can be placed anywhere on the command line, even after the filenames.
Options apply to all files, regardless of where they appear.

The default is to dump 16 bytes. Use the -n option to change this number.

The -o option can be negative, e.g. "-o-16".

Each file's hex dump starts at some "key position", which by default is the
beginning of the file. If the key position is not valid for a file, its hex
dump will be blank.

The -kexe... options are mainly for DOS EXE files, except for -kexesig which
is for newer EXE files.

The -kcomjmp option is for files that begin with byte 0xe9 or 0xeb.
