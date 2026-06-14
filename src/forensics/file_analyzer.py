import os

SIGNATURES = [
    (b'\x89PNG\r\n\x1a\n', 0, 'PNG image'),
    (b'\xff\xd8\xff', 0, 'JPEG image'),
    (b'GIF87a', 0, 'GIF image'),
    (b'GIF89a', 0, 'GIF image'),
    (b'BM', 0, 'BMP image'),
    (b'RIFF', 0, 'RIFF / WAV / AVI'),
    (b'%PDF', 0, 'PDF document'),
    (b'PK\x03\x04', 0, 'ZIP archive / Office doc'),
    (b'PK\x05\x06', 0, 'ZIP archive (empty)'),
    (b'PK\x07\x08', 0, 'ZIP archive (spanned)'),
    (b'Rar!\x1a\x07', 0, 'RAR archive'),
    (b'\x1f\x8b\x08', 0, 'GZIP compressed'),
    (b'BZh', 0, 'BZ2 compressed'),
    (b'\xfd7zXZ\x00', 0, 'XZ compressed'),
    (b'\x75\x73\x74\x61\x72', 257, 'TAR archive (USTAR)'),
    (b'!<arch>\n', 0, 'AR archive'),
    (b'\x7fELF', 0, 'ELF binary'),
    (b'MZ', 0, 'PE (Windows executable / DLL)'),
    (b'\xca\xfe\xba\xbe', 0, 'Java class file'),
    (b'\xfe\xed\xfa\xce', 0, 'Mach-O (32-bit)'),
    (b'\xfe\xed\xfa\xcf', 0, 'Mach-O (64-bit)'),
    (b'\xce\xfa\xed\xfe', 0, 'Mach-O (reverse 32-bit)'),
    (b'\xcf\xfa\xed\xfe', 0, 'Mach-O (reverse 64-bit)'),
    (b'\x00\x01\x00\x00\x00', 0, 'TrueType font'),
    (b'OTTO', 0, 'OpenType font'),
    (b'wOFF', 0, 'WOFF font'),
    (b'\x1a\x45\xdf\xa3', 0, 'WebM / Matroska media'),
    (b'\x00\x00\x00 ftyp', 0, 'MP4 / MOV / 3GP'),
    (b'\x00\x00\x00\x1cftyp', 0, 'MP4 / MOV / 3GP'),
    (b'\x00\x00\x00\x18ftyp', 0, 'MP4 / MOV / 3GP'),
    (b'\x49\x44\x33', 0, 'MP3 (ID3 tag)'),
    (b'\xff\xfb', 0, 'MP3'),
    (b'\xff\xf3', 0, 'MP3'),
    (b'\xff\xf2', 0, 'MP3'),
    (b'\x66\x4c\x61\x43', 0, 'FLAC audio'),
    (b'fLaC', 0, 'FLAC audio'),
    (b'OggS', 0, 'OGG container'),
    (b'\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a\x87\x0a', 0, 'JPEG 2000'),
    (b'\xff\x0a', 0, 'JPEG 2000 codestream'),
    (b'\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a\x87\x0a', 0, 'JPEG 2000'),
    (b'\x0a\x0d\x87\x0a', 4, 'JPEG 2000 (alternative)'),
    (b'\x1f\x9d', 0, 'TAR archive (LZW)'),
    (b'\x1f\xa0', 0, 'TAR archive (LZH)'),
    (b'\x42\x43\x50\x46', 0, 'BCPFE (Windows update)'),
    (b'FLIF', 0, 'FLIF image'),
    (b'\x04\x22\x4d\x18', 0, 'LZ4 compressed'),
    (b'\x28\xb5\x2f\xfd', 0, 'Zstandard compressed'),
    (b'\x37\x7a\xbc\xaf\x27\x1c', 0, '7-Zip archive'),
    (b'\x03\x00\x00\x00', 0, 'Compound File (OLE / MSI / DOC)'),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 0, 'Compound File Binary (OLE2 / MSI / DOC / XLS)'),
    (b'l\x01', 0, 'FAT disk image / Boot sector'),
    (b'\x53\x43\x43\x41', 0, 'SCCA (FTK / EnCase)'),
    (b'SQLite format 3\x00', 0, 'SQLite database'),
    (b'dex\n035\x00', 0, 'Dalvik EXecutable (DEX)'),
    (b'dex\n037\x00', 0, 'Dalvik EXecutable (DEX)'),
    (b'\xde\xa0\x00\x00\x00\x38\x06\x40', 0, 'Android OAT'),
    (b'<html', 0, 'HTML text'),
    (b'<!DOCTYPE html', 0, 'HTML document'),
]


class FileAnalyzer:
    def run(self):
        print("\n=== File Analyzer ===")
        path = input("File path: ").strip()
        if not os.path.exists(path):
            print("File not found.")
            return

        with open(path, 'rb') as f:
            header = f.read(512)

        results = []
        for sig, offset, desc in SIGNATURES:
            if header[offset:offset + len(sig)] == sig:
                results.append(desc)

        size = os.path.getsize(path)
        print(f"\nFile: {os.path.basename(path)}")
        print(f"Size: {size:,} bytes")

        if results:
            print("Detected types:")
            for r in results:
                print(f"  \033[92m\u2713\033[0m {r}")
        else:
            print("No known signature matched.")
            print(f"First 32 hex bytes: {header[:32].hex(' ')}")
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in header[:64])
            print(f"Printable preview: {printable}")

    def get_result(self):
        return {'tool': 'File Analyzer'}
