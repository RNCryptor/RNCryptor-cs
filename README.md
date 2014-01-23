RNCryptor-cs
============

C# implementation of Rob Napier's RNCryptor

**Note:** This codebase is in early alpha stage. Don't expect it to do much yet.

This project was developed using Mono on Mac OSX. Its compatibility with Windows
platforms is presently unknown.

To build on OSX, make sure you've got the Mono compiler installed, then run
`xbuild RNCryptor.csproj`.  To run it, you can then do this: `mono bin/Debug/RNCryptor.exe`.
It only runs test at the moment, but at least this way we can see what we still need to work on.

All tests are known to pass.  Tests cover RNCryptor schemas through version 2.

License: MIT

