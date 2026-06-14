import struct
import os

class ExifViewer:
    def run(self):
        print("\n=== EXIF / Metadata Viewer ===")
        path = input("File path: ").strip()
        if not os.path.exists(path):
            print("File not found.")
            return

        with open(path, 'rb') as f:
            data = f.read()

        if data[:2] == b'\xff\xd8':
            self._parse_jpeg(data)
        elif data[:8] == b'\x89PNG\r\n\x1a\n':
            self._parse_png(data)
        else:
            size = os.path.getsize(path)
            print(f"File: {os.path.basename(path)}")
            print(f"Size: {size:,} bytes")
            print("No EXIF metadata (unsupported format).")
            print("Showing first 64 bytes as hex:")
            print(data[:64].hex(' '))

    def _parse_jpeg(self, data):
        print("JPEG file detected.")
        i = 2
        found = False
        while i < len(data) - 4:
            if data[i] != 0xFF:
                i += 1
                continue
            marker = data[i+1]
            if marker == 0xE1:
                seg_len = struct.unpack('>H', data[i+2:i+4])[0]
                exif = data[i+4:i+4+seg_len-2]
                found = True
                self._dump_exif(exif)
                i += 2 + seg_len
            elif marker == 0xE0:
                seg_len = struct.unpack('>H', data[i+2:i+4])[0]
                print(f"  JFIF/APP0: {data[i+4:i+4+seg_len-2].decode('latin-1', errors='replace')[:32]}")
                i += 2 + seg_len
            elif marker == 0xFE:
                seg_len = struct.unpack('>H', data[i+2:i+4])[0]
                comment = data[i+4:i+4+seg_len-2]
                print(f"  Comment: {comment.decode('latin-1', errors='replace')}")
                i += 2 + seg_len
            elif marker == 0xDB or marker == 0xC0 or marker == 0xC4 or marker == 0xDA:
                seg_len = struct.unpack('>H', data[i+2:i+4])[0] if data[i+2:i+4] else 0
                i += 2 + (seg_len or 0)
            else:
                i += 1

        if not found:
            print("  No EXIF data found.")

    def _parse_png(self, data):
        print("PNG file detected.")
        i = 8
        while i < len(data) - 4:
            length = struct.unpack('>I', data[i:i+4])[0]
            chunk_type = data[i+4:i+8].decode('latin-1', errors='replace')
            if chunk_type == 'IEND':
                break
            if chunk_type == 'tEXt':
                chunk_data = data[i+8:i+8+length]
                null_pos = chunk_data.find(b'\x00')
                if null_pos >= 0:
                    key = chunk_data[:null_pos].decode('latin-1', errors='replace')
                    val = chunk_data[null_pos+1:].decode('latin-1', errors='replace')
                    print(f"  {key}: {val}")
            elif chunk_type == 'zTXt':
                chunk_data = data[i+8:i+8+length]
                null_pos = chunk_data.find(b'\x00')
                if null_pos >= 0:
                    key = chunk_data[:null_pos].decode('latin-1', errors='replace')
                    print(f"  {key}: <compressed>")
            elif chunk_type == 'iTXt':
                print(f"  <i18n text chunk: {length} bytes>")
            elif chunk_type == 'IHDR':
                w, h = struct.unpack('>II', data[i+8:i+16])
                print(f"  Dimensions: {w}x{h}")
            elif chunk_type == 'gAMA':
                gamma = struct.unpack('>I', data[i+8:i+12])[0] / 100000
                print(f"  Gamma: {gamma}")
            i += 12 + length

    def _dump_exif(self, data):
        if data[:4] != b'Exif':
            print("  Malformed EXIF header")
            return
        print("  EXIF data present:")
        if len(data) > 8:
            txt = data[6:].decode('latin-1', errors='replace')
            printable = ''.join(c if c.isprintable() or c in '\n\r\t' else '.' for c in txt)
            for line in printable.split('\n')[:20]:
                line = line.strip()
                if line:
                    print(f"    {line[:120]}")

    def get_result(self):
        return {'tool': 'EXIF Viewer'}
