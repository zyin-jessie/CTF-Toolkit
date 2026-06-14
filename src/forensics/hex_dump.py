import os

class HexDump:
    def run(self):
        print("\n=== Hex Dump ===")
        path = input("File path: ").strip()
        if not os.path.exists(path):
            print("File not found.")
            return

        try:
            offset_str = input("Start offset (default 0): ").strip()
            start = int(offset_str, 0) if offset_str else 0
        except ValueError:
            start = 0

        try:
            length_str = input("Length in bytes (default 512, max 4096): ").strip()
            length = min(int(length_str), 4096) if length_str else 512
        except ValueError:
            length = 512

        with open(path, 'rb') as f:
            f.seek(start)
            data = f.read(length)

        print(f"\nHex dump of {os.path.basename(path)} (offset {start:#x}, {len(data)} bytes):\n")
        i = 0
        while i < len(data):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            hex_part = hex_part.ljust(47)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            print(f"{start+i:08x}  {hex_part}  |{ascii_part}|")
            i += 16

    def get_result(self):
        return {'tool': 'Hex Dump'}
