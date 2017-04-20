# Truehunter
The goal of Truehunter is to detect encrypted containers using a fast and memory efficient approach. It was designed as a PoC for detecting TrueCrypt containers, however it should pickup some other files with an unknown header and high entropy.
## Installation
Just use with Python 2.7, it does not need any additional libraries. 
## Usage
The headers database file will be created with the first use, and can be updated after every scan. Note this is not a correct header database, just the first 4 bytes of every file and the extension (It does the job as a PoC).

usage: truehunter.py [-h] [-D HEADERSFILE] [-m MINSIZE] [-M MAXSIZE]  
                     [-R MAXHEADER] [-f] [-o OUTPUTFILE]  
                     LOCATION  
  
Checks for file size, unknown header, and entropy of files to determine if  
they are encrypted containers.  

positional arguments:  
  LOCATION              Drive or directory to scan.  

optional arguments:  
  -h, --help            show this help message and exit . 
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
