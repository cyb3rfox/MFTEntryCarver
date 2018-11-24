# MFTEntryCarver
Carve files for MFT entries (eg. blkls output or memory dumps). Recovers filenames (long &amp; short), timestamps ($STD &amp; $FN) and data if resident. It will also parse half broken entries as long as at least one $FN entry is ok.
There is a mored detailed description of how and why I wrote that and how you can use it. I'm not really a developer but just an DFIR guy. So please excuse the spaghetti code.

## MFT
NTFS stores it's metadata in the $MFT file which references itself in MFT record number 0. MFT records are well defined as described here (http://www.cse.scu.edu/~tschwarz/coen252_07Fall/Lectures/NTFS.html)
Obviously it's growing over time. When one deletes a file, corresponding entry will be marked as free but the entry data remains there until it's overwritten. Generally that implies, that it is still inside the addressed space of $MFT.
However experimenting a little bit with unallocated space on a test Windows 7 system image showed, that scanning for NTFS Entry headers (FILE) showed over 50.000 results in a 8Gb junk of unallocated space.
I don't really know how those entries end up there but I guess it's a combination of various causes. Some of them might be comming when parts of memory are ending uop on the drive in files like crashdumps and then the files are being deleted.

#How to get unallocated space
I used Sleuthkit's blkls to get the unallocated blocks of an image. 


