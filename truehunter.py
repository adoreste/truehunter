#!/usr/bin/python
# This tool has been created as a PoC.

import sys, math, os, argparse, hashlib, shutil, csv, sqlite3, time
from collections import Counter

class truehunter:
    def __init__(self, database, minFileSize, maxFileSize, maxHeaderRep, ouputFile):
        self.db = db_utils(database)
        self.minFileSize = minFileSize
        self.maxFileSize = maxFileSize
        self.maxHeaderRep = maxHeaderRep
        self.repeatedHeaders = self.db.getallheaders()
        self.firstCheck = []
        self.fastScanPositives = []
        self.slowScanPositives = []
        self.ignoredFiles = []  # Bigger than maxFileSize
        self.outputFile = ouputFile
        self.fullScanCompleted = False

    def fastScan(self, location):
        # Step one, check size and read first 4 bytes
        for (path, subdir, files) in os.walk(location):
            for filename in files:
                filePath = os.path.join(path, filename)
                try:
                    fileSize = os.path.getsize(filePath) / 1024
                    if (fileSize % 128 == 0) and (fileSize > self.minFileSize):
                        header = open(filePath, 'rb').read(4).encode('hex').upper()  # Read first 4 bytes, referenced as header but it's not.
                        dbresult = self.db.getheader(header)
                        if dbresult is not None:  # Quick and dirty way to check if there is something in the db
                            continue
                        if header in self.repeatedHeaders:
                            self.repeatedHeaders[header][0] += 1
                        else:
                            self.repeatedHeaders[header] = [1, filename]
                        self.firstCheck.append([filePath, fileSize, header])
                except:
                    print '[!] Error reading %s' % (filePath)
        # Step two, check for header repetitions
        for (filePath, fileSize, header) in self.firstCheck:
            if self.repeatedHeaders[header][0] <= self.maxHeaderRep:
                self.fastScanPositives.append({'Path': filePath, 'File Size': fileSize, 'Header': header})

    def slowScan(self):
        # Memory efficient entropy calculation
        for item in self.fastScanPositives:
            filePath = item['Path']
            header = item['Header']
            fileSize = os.path.getsize(filePath)
            entropy = 0.0
            md5HashFunc = hashlib.md5()
            if (fileSize / 1024) <= self.maxFileSize:
                hexFreq = {}
                decFreq = {}
                with open(filePath, 'rb') as file:
                    # Read chunks instead of mapping the whole file
                    while True:
                        dataChunk = file.read(65535)
                        if not dataChunk:
                            break
                        md5HashFunc.update(dataChunk)
                        hexFreq = Counter(hexFreq) + (Counter(dataChunk))
                # Transform (hex)byte values to (dec)byte and prepare counters for entropy calculation.
                for byte in hexFreq:
                    decFreq[ord(byte)] = float(hexFreq[byte]) / float(fileSize)
                # Entropy calculation.
                for repetition in decFreq.values():
                    if repetition > 0:
                        entropy -= repetition * math.log(repetition, 2)
                if entropy > 7.998:
                    self.slowScanPositives.append({'Path': filePath, 'Entropy': entropy, 'MD5 Hash': md5HashFunc.hexdigest(),
                         'File Size': fileSize, 'Header': header})
            else:
                self.ignoredFiles.append(
                    {'Path': filePath, 'Entropy': 'Not calculated', 'File Size': fileSize, 'Header': header})
        self.fullScanCompleted = True

    def writeResults(self):
        # Write results to a CSV file
        with open(self.outputFile, 'w') as csvfile:
            fieldNames = ['Path', 'Entropy', 'MD5 Hash', 'File Size', 'Header']
            writer = csv.DictWriter(csvfile, fieldnames=fieldNames, dialect=csv.excel)
            writer.writeheader()
            if self.fullScanCompleted:
                if len(self.slowScanPositives) > 0:
                    writer.writerows(self.slowScanPositives)
                else:
                    print '[!] No files detected.'
                if len(self.ignoredFiles) > 0:
                    writer.writerows(self.ignoredFiles)
                    print '[+] Manually check ignored files or repeat the scan increasing the maximum file size to scan (-M, --maxsize).'
            else:
                if len(self.fastScanPositives) > 0:
                    writer.writerows(self.fastScanPositives)
                else:
                    print '[!] No files detected.'

    def addRepeatedHeaders(self):
        # Update headers.db
        headers = []
        for item in self.repeatedHeaders:
            # Only update if header repetition count is bigger than 10
            if self.repeatedHeaders.get(item)[0] < 10: continue
            try:
                extension = self.repeatedHeaders.get(item)[1][::-1].split('.')[0][::-1]
            except:
                extension = ''
            header = item
            headers.append([header, extension])
        self.db.updatedb(headers)

class db_utils:
    def __init__(self, databaseFile):
        # Check if the db file exists.
        if not os.path.isfile(databaseFile):
            self.createdb(databaseFile)
        else:
            self.conn = sqlite3.connect(databaseFile)
            self.c = self.conn.cursor()

    def createdb(self, databaseFile):
        # Create Database
        self.conn = sqlite3.connect(databaseFile)
        self.c = self.conn.cursor()
        # Create table
        self.c.execute('''CREATE TABLE headers
                     (header text, extension text, date text)''')
        # Save (commit) the changes
        self.conn.commit()

    def updatedb(self, headersarray):
        date = time.strftime("%d/%m/%Y")
        # headersarray must contain arrays ['header','extension']
        for header, extension in headersarray:
            data = (header, extension, date,)
            if self.getheader(header) is not None: continue # avoid adding repeated headers
            else: self.c.execute('INSERT INTO headers VALUES (?,?,?)', data)
        self.conn.commit()

    def getheader(self, header):
        self.c.execute('SELECT * FROM headers WHERE header=?', (header,))
        return self.c.fetchone()

    def getallheaders(self):
        self.c.execute('SELECT Header FROM headers')
        x = self.c.fetchall()
        headers = {}
        if len(x) == 0:
            return headers
        for header in x:
            headers[header[0]] = 0
        return headers

    def closedb(self):
        self.conn.commit()
        self.conn.close()


def updatedb(th, database):
    updatedb = raw_input('[?] Include repeated headers from this scan into the database? [Y/N]')
    if updatedb.lower() == 'y':
        shutil.copyfile(database, 'headers.db.bck')
        print '[+] Database backup saved as headers.db.bck'
        th.addRepeatedHeaders()
        print '[+] Database updated.'
    print '[+] Bye!'
    sys.exit(0)

def main():
    description = ''' _                   _                 _            
| |                 | |               | |           
| |_ _ __ _   _  ___| |__  _   _ _ __ | |_ ___ _ __ 
| __| '__| | | |/ _ \ '_ \| | | | '_ \| __/ _ \ '__|
| |_| |  | |_| |  __/ | | | |_| | | | | ||  __/ |   
 \__|_|   \__,_|\___|_| |_|\__,_|_| |_|\__\___|_|   
[+] Truehunter detects TrueCrypt containers and similar files.\n[+] Autor: Andres Doreste\n[+] LinkedIn: https://www.linkedin.com/in/andres-doreste-239471136/\n[+] Notes: This project it's just a PoC, there will be dragons!\n'''
    print description

    parser = argparse.ArgumentParser(
        description='Checks for file size, unknown header, and entropy of files to determine if they are encrypted containers.')
    parser.add_argument('LOCATION', help='Drive or directory to scan.')
    parser.add_argument('-D', '--database', dest='headersFile', default='headers.db',
                        help='Headers database file, default headers.db')
    parser.add_argument('-m', '--minsize', dest='minSize', default=1024, type=int,
                        help='Minimum file size in Kb, default 1Mb.')
    parser.add_argument('-M', '--maxsize', dest='maxSize', default=102400, type=int,
                        help='Maximum file size in Kb, default 100Mb.')
    parser.add_argument('-R', '--repeatHeader', dest='maxHeader', default=3, type=int,
                        help='Discard files with unknown headers repeated more than N times, default 3.')
    parser.add_argument('-f', '--fast', dest='fastScan', action='store_true', help='Do not calculate entropy.')
    parser.add_argument('-o', '--outputfile', dest='outputFile', default='scan_results.csv',
                        help='Scan results file name, default scan_results.csv')
    args = parser.parse_args()

    if not os.path.exists(args.LOCATION):
        print '[!] Could not read ' + args.LOCATION
        sys.exit(0)

    th = truehunter(args.headersFile, args.minSize, args.maxSize, args.maxHeader, args.outputFile)
    startTime = time.time()

    print '[+] Starting fast scan, it shouldn\'t take too long...'
    th.fastScan(args.LOCATION)

    print '[+] %s files detected.'%(len(th.fastScanPositives))
    print '[+] Done!'

    if args.fastScan:
        print '[!] Scan finished in %.2f seconds.\n' % (time.time() - startTime)
        th.writeResults()
        updatedb(th, args.headersFile)

    print '[+] Starting entropy scan, staring at the screen won\'t help, better grab a coffee...'
    th.slowScan()

    print '[+] %s files detected.'%(len(th.slowScanPositives))
    print '[!] %s files possible encrypted files ignored'%(len(th.ignoredFiles))
    print '[+] Done!'
    th.writeResults()
    updatedb(th, args.headersFile)

if __name__ == '__main__':
    main()