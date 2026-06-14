import os
import re

class Strings:
    def run(self):
        print("\n=== Strings Extractor ===")
        path = input("File path: ").strip()
        if not os.path.exists(path):
            print("File not found.")
            return

        try:
            min_len_str = input("Minimum string length (default 4): ").strip()
            min_len = int(min_len_str) if min_len_str else 4
        except ValueError:
            min_len = 4

        print(f"\nExtracting strings (min length {min_len}) from {os.path.basename(path)}...\n")
        count = 0
        try:
            with open(path, 'rb') as f:
                data = f.read()

            pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_len)
            for match in pattern.finditer(data):
                s = match.group().decode('ascii')
                print(s)
                count += 1

            print(f"\n--- {count} strings found ---")

        except MemoryError:
            print("File too large, reading in chunks...")
            pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_len)
            buf = b''
            with open(path, 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    buf += chunk
                    while len(buf) > min_len:
                        m = pattern.search(buf)
                        if m:
                            s = m.group().decode('ascii', errors='replace')
                            print(s)
                            count += 1
                            buf = buf[m.end():]
                        else:
                            buf = buf[-(min_len-1):]
                            break
                    if len(buf) > 65536 + min_len:
                        buf = buf[-min_len:]
            print(f"\n--- {count} strings found ---")

    def get_result(self):
        return {'tool': 'Strings Extractor'}
