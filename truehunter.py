#!/usr/bin/python
# This tool has been created as a PoC.

import argparse
import csv
import hashlib
import math
import os
import sys
import shutil
import sqlite3
import sys
import time
from binascii import hexlify
from collections import Counter

class TrueHunter:
    def __init__(self, database, min_file_size, max_file_size, max_header_count, output_file):
        self.db = DbUtils(database)
        self.min_file_size = min_file_size
        self.max_file_size = max_file_size
        self.max_header_count = max_header_count
        self.repeated_headers = self.db.get_all_headers()
        self.first_check = []
        self.fast_scan_positives = []
        self.slow_scan_positives = []
        self.ignored_files = []  # Bigger than maxFileSize
        self.output_file = output_file
        self.full_scan_completed = False

    def fast_scan(self, location):
        # Step one, check size and read first 8 bytes
        for (path, subdir, files) in os.walk(location):
            for filename in files:
                file_path = os.path.join(path, filename)
                try:
                    file_size = os.path.getsize(file_path) / 1024
                    if (file_size % 64 == 0) and (file_size > self.min_file_size):
                        # Read first 8 bytes, not a real header.
                        header = hexlify(open(file_path, "rb").read(8)).decode("utf-8")
                        if header in self.repeated_headers:
                            self.repeated_headers[header][0] += 1
                        else:
                            self.repeated_headers[header] = [1, filename]
                        self.first_check.append([file_path, file_size, header])
                except:
                    print("[!] Error reading {}".format(file_path))
        # Step two, check for header repetitions
        for (file_path, file_size, header) in self.first_check:
            if self.repeated_headers[header][0] <= self.max_header_count:
                self.fast_scan_positives.append({"Path": file_path,
                                                "File Size": file_size, 
                                                "Header": header})

    def slow_scan(self):
        # Memory efficient entropy calculation
        for item in self.fast_scan_positives:
            file_path = item.get("Path")
            header = item.get("Header")
            file_size = os.path.getsize(file_path)
            entropy = 0.0
            hash_func = hashlib.md5()
            if (file_size / 1024) <= self.max_file_size:
                hex_freq = {}
                dec_freq = {}
                with open(file_path, "rb") as f:
                    # Read chunks instead of mapping the whole file
                    while True:
                        data_chunk = f.read(65535)
                        if not data_chunk:
                            break
                        hash_func.update(data_chunk)
                        hex_freq = Counter(hex_freq) + (Counter(data_chunk))
                # Transform (hex)byte values to (dec)byte and prepare counters for entropy calculation.
                for byte in hex_freq:
                    dec_freq[byte] = float(hex_freq[byte]) / float(file_size)
                # Entropy calculation.
                for repetition in dec_freq.values():
                    if repetition > 0:
                        entropy -= repetition * math.log(repetition, 2)
                if entropy > 7.998:
                    self.slow_scan_positives.append(
                        {"Path": file_path, 
                        "Entropy": entropy, "MD5 Hash": hash_func.hexdigest(),
                         "File Size": file_size, "Header": header})
            else:
                self.ignored_files.append(
                    {"Path": file_path,
                    "Entropy": "Not calculated", 
                    "File Size": file_size, 
                    "Header": header})
        self.full_scan_completed = True

    def write_results(self):
        # Write results to a CSV file
        with open(self.output_file, 'w') as csvfile:
            field_names = ["Path", "Entropy", "MD5 Hash", "File Size", "Header"]
            writer = csv.DictWriter(csvfile, fieldnames=field_names, dialect=csv.excel)
            writer.writeheader()
            if self.full_scan_completed:
                if len(self.slow_scan_positives) > 0:
                    writer.writerows(self.slow_scan_positives)
                else:
                    print("[!] No files detected.")
                if len(self.ignored_files) > 0:
                    writer.writerows(self.ignored_files)
                    print("[+] Manually check ignored files or repeat the scan increasing the maximum file size to " \
                          "scan (-M, --maxsize). ")
            else:
                if len(self.fast_scan_positives) > 0:
                    writer.writerows(self.fast_scan_positives)
                else:
                    print("[!] No files detected.")

    def add_repeated_headers(self):
        # Update headers.db
        headers = []
        for item in self.repeated_headers:
            # Only update if header repetition count is bigger than 10
            if self.repeated_headers.get(item)[0] < 10:
                continue
            try:
                extension = self.repeated_headers.get(item)[1][::-1].split('.')[0][::-1]
            except:
                extension = ""
            header = item
            headers.append([header, extension])
        self.db.update_db(headers)


class DbUtils:
    def __init__(self, database_file):
        # Check if the db file exists.
        if not os.path.isfile(database_file):
            self.create_db(database_file)
        else:
            self.conn = sqlite3.connect(database_file)
            self.c = self.conn.cursor()

    def create_db(self, database_file):
        # Create Database
        self.conn = sqlite3.connect(database_file)
        self.c = self.conn.cursor()
        # Create table
        self.c.execute('''CREATE TABLE headers
                     (header text, extension text, date text)''')
        # Save (commit) the changes
        self.conn.commit()

    def update_db(self, headers_array):
        date = time.strftime("%d/%m/%Y")
        # headers array must contain arrays ['header','extension']
        for header, extension in headers_array:
            data = (header, extension, date,)
            if self.get_header(header) is not None:
                continue  # avoid adding repeated headers
            else:
                self.c.execute('INSERT INTO headers VALUES (?,?,?)', data)
        self.conn.commit()

    def get_header(self, header):
        self.c.execute('SELECT * FROM headers WHERE header=?', (header,))
        return self.c.fetchone()

    def get_all_headers(self):
        self.c.execute('SELECT Header FROM headers')
        x = self.c.fetchall()
        headers = {}
        if len(x) == 0:
            return headers
        for header in x:
            headers[header[0]] = 0
        return headers

    def close_db(self):
        self.conn.commit()
        self.conn.close()


def update_db(th, database):
    if sys.version_info.major > 2:
        update = input("[?] Save repeated headers from this scan? [Y/N]")
    else:
        update = raw_input("[?] Save repeated headers from this scan? [Y/N]")
    if update.lower() == "y":
        try:
            shutil.copyfile(database, "headers.db.bck")
            print("[+] Database backup saved as headers.db.bck")
        except IOError:
            print("[!] Could not backup the existing database")
            sys.exit(0)
        th.add_repeated_headers()
        print("[+] Database updated.")
    sys.exit(0)


def main():
    description = """ _                   _                 _            
| |                 | |               | |           
| |_ _ __ _   _  ___| |__  _   _ _ __ | |_ ___ _ __ 
| __| "__| | | |/ _ \ '_ \| | | | '_ \| __/ _ \ '__|
| |_| |  | |_| |  __/ | | | |_| | | | | ||  __/ |   
 \__|_|   \__,_|\___|_| |_|\__,_|_| |_|\__\___|_|   
[+] Truehunter detects TrueCrypt containers and high entropy files (probably encrypted).\n[+] Autor: Andres Doreste\n[+] LinkedIn: https://www.linkedin.com/in/andres-doreste-239471136/\n[+] Notes: This project it's just a PoC\n"""
    print(description)

    parser = argparse.ArgumentParser(
        description="Checks for file size, unknown header, and entropy of files to determine if they are encrypted containers.")
    parser.add_argument("LOCATION", help="Drive or directory to scan.")
    parser.add_argument("-D", "--database", dest="headers_file", default="headers.db",
                        help="Headers database file, default headers.db")
    parser.add_argument("-m", "--minsize", dest="min_size", default=1024, type=int,
                        help="Minimum file size in Kb, default 1Mb.")
    parser.add_argument("-M", "--maxsize", dest="max_size", default=102400, type=int,
                        help="Maximum file size in Kb, default 100Mb.")
    parser.add_argument("-R", "--repeatHeader", dest="max_header", default=3, type=int,
                        help="Discard files with unknown headers repeated more than N times, default 3.")
    parser.add_argument("-f", "--fast", dest="fast_scan", action="store_true", help="Do not calculate entropy.")
    parser.add_argument("-o", "--outputfile", dest="output_file", default="scan_results.csv",
                        help="Scan results file name, default scan_results.csv")
    args = parser.parse_args()

    if not os.path.exists(args.LOCATION):
        print("[!] Could not read {}".format(args.LOCATION))
        sys.exit(0)

    th = TrueHunter(args.headers_file, args.min_size, args.max_size, args.max_header, args.output_file)
    start_time = time.time()

    print("[>] Starting fast scan, it shouldn't take too long...")
    th.fast_scan(args.LOCATION)

    print("[+] {} files detected.".format(len(th.fast_scan_positives)))
    print("[>] Done!")

    if args.fast_scan:
        print("[!] Scan finished in {0:.2f} seconds.".format(time.time() - start_time))
        th.write_results()
        update_db(th, args.headers_file)

    print("[>] Starting entropy scan, staring at the screen won't help at this moment...")
    th.slow_scan()

    print("[+] {} files detected.".format(len(th.slow_scan_positives)))
    print("[!] {} files possible encrypted files ignored".format(len(th.ignored_files)))
    th.write_results()
    print("[+] Results saved in {}".format(args.output_file))
    print("[>] Scan finished")
    update_db(th, args.headers_file)

if __name__ == "__main__":
    main()
