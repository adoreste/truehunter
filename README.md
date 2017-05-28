# Truehunter
The goal of Truehunter is to detect encrypted containers using a fast and memory efficient approach without any external dependencies for ease of portability. It was designed to detect Truecrypt and Veracrypt containers, however it may detect any encrypted file with a 'header' not included in its database.  
  
Truehunter performs the following checks:
1. Test the first 4 bytes of the file against its own database.  
2. File size modulo 64 must be zero.  
3. Checks for file entropy.  
  
Truehunter is part of BlackArch forensic tools. 
https://blackarch.org/forensic.html

## Installation
Just use with Python 2.7, it does not need any additional libraries. 
  
## Usage  
  
The headers database file will be created with the first use, and can be updated after every scan. Note this is not a correct header database, just the first 4 bytes of every file, extension and date(It does the job as a PoC).  
  
Fast Scan: Searchs for files with a size % 64 = 0 (block ciphers), unknown headers and appearing less than MAXHEADER value (default 3).  
Default Scan: Performs a fast scan and calculates the entropy of the resulting files to reduce false positives.  
  
usage: truehunter.py [-h] [-D HEADERSFILE] [-m MINSIZE] [-M MAXSIZE]  
                     [-R MAXHEADER] [-f] [-o OUTPUTFILE]  
                      LOCATION  
  
Checks for file size, unknown header, and entropy of files to determine if  
they are encrypted containers.  
  
positional arguments:  
  LOCATION              Drive or directory to scan.  

optional arguments:  
  -h, --help            show this help message and exit.   
  -D HEADERSFILE, --database HEADERSFILE  
                        Headers database file, default headers.db  
  -m MINSIZE, --minsize MINSIZE  
                        Minimum file size in Kb, default 1Mb.  
  -M MAXSIZE, --maxsize MAXSIZE  
                        Maximum file size in Kb, default 100Mb.  
  -R MAXHEADER, --repeatHeader MAXHEADER  
                        Discard files with unknown headers repeated more than  
                        N times, default 3.  
  -f, --fast            Do not calculate entropy.  
  -o OUTPUTFILE, --outputfile OUTPUTFILE  
                        Scan results file name, default scan_results.csv  
  
## License: GPLv3
  
Truehunter  
Author Andres Doreste  
Copyright (C) 2015, Andres Doreste  
License:   GPLv3  
