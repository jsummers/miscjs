Mkbgb_j
A script to create a BGB file from a BMP file
Copyright (C) 2025 Jason Summers
https://github.com/jsummers/miscjs -> mkbgb_j
Terms of use: MIT license. See COPYING.txt.

BGB is a "background" image format for Microsoft Comic Chat.

For some brief instructions, run mkbgb_j.py without parameters.

========== Notes ==========

This script is not very sophisticated. If something goes wrong, it's normal for
it to crash gracefully.

Not every BMP file will work as a source image. Some will be rejected, for
example if they use RLE compression. Others might be allowed by Mkbgb_j, while
the generated BGB file doesn't actually work in Comic Chat (sorry, but I don't
know exactly what Comic Chat's requirements are).

========== Notes for Windows users ==========

Comic Chat is a Windows program, and Mkbgb_j is a Python script, which I
acknowledge is not ideal for most Windows users. So, for what it's worth, here
are a few notes about how you might run Mkbgb_j on Windows.

Download at least the mkbgb_j.py file, and put it in a folder of your choice.
I'll assume it's C:\Users\[username]\Documents\mkbgb_j, where [username] is
your Windows username.

Download and install the Windows version of Python, from
https://www.python.org/. You can use the default installation options, or
change/disable some things if you want. A fairly minimal Python installation
should suffice.

(The only Python library Mkgbg_j needs is zlib, and zlib seems to be included
in the standard Python installation, so you shouldn't have to install anything
else.)

Run a command prompt (Start -> Search for "command prompt").

"cd" to the folder containing the mkbgb_j.py file.

C:\Users\[username]>cd Documents\mkbgb_j

To test it:

C:\Users\[username]\Documents\mkbgb_j>py mkbgb_j.py

If the "py" command doesn't work, a last resort might be to use the full path
of your python.exe file, which could be something like:

C:\Users\[username]\Documents\mkbgb_j>"C:\Users\[username]\AppData\Local\Programs\Python\Python[version]\python.exe" mkbgb_j.py

====================
