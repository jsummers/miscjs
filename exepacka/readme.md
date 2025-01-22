# exepacka.py

By Jason Summers.

Terms of use: MIT license. See COPYING.txt.

Exepacka (exepacka.py) is a Python script that analyzes an EXEPACK-compressed
DOS EXE file, and prints the compression parameters.

It is conceptually similar to, and largely derived from, my Pkla script for
PKLITE-compressed files.

-----

The "-p" option causes each output item to be tagged with an indication
of its importance with respect to decompressing the file. The following
tags are used:

* "CRIT" - Needed to decompress the main part of the program.
* "HIGH" - Needed to decompress to a runnable file.
* "MED" - Useful for best results.
* "LOW" - Might have *some* use.
* "INFO" - Not needed.

These tags are somewhat arbitrary in cases where multiple items give the
same information.

Note that there are additional fields in the EXEPACK header that you'll
have to read, if you want to properly decompress the file.

-----

Exepacka is not able to decompress files. I have no immediate plans to add
such a feature. (One way to decompress such files is to use my Deark
utility.)
