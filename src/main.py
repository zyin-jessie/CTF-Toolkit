#!/usr/bin/env python3.14
from utils.banner import Banner
from utils.menu import Menu
from decryption.hash_crack import HashCrack
from decryption.hash_identifier import HashIdentifier
from decryption.multi_hash_crack import MultiHashCrack
from decryption.cipher_identifier import CipherIdentifier
from encoding.encdec import EncDec
from steganography.lsb import LSBSteg
from steganography.exif import ExifViewer
from forensics.file_analyzer import FileAnalyzer
from forensics.hex_dump import HexDump
from forensics.strings import Strings
from misc.password_gen import PasswordGen
from misc.jwt_decode import JWTDecode
from misc.converter import Converter

class PwnStarToolkit:
    def __init__(self):
        self.banner = Banner()
        self.hash = HashCrack()
        self.hash_id = HashIdentifier()
        self.multi_hash = MultiHashCrack()
        self.cipher_id = CipherIdentifier()
        self.encdec = EncDec()
        self.lsb = LSBSteg()
        self.exif = ExifViewer()
        self.file_analyzer = FileAnalyzer()
        self.hex_dump = HexDump()
        self.strings = Strings()
        self.password_gen = PasswordGen()
        self.jwt_decode = JWTDecode()
        self.converter = Converter()

        self.run()

    def run(self):
        main_items = [
            "Hash Tool",
            "Cipher Tools",
            "Steganography",
            "Forensics",
            "Misc Tools",
            "Exit",
        ]

        while True:
            print()
            menu = Menu(main_items)
            choice = menu.run()
            print()

            if choice == 0:
                self._hash_tool_menu()
            elif choice == 1:
                self._cipher_tools_menu()
            elif choice == 2:
                self._stego_menu()
            elif choice == 3:
                self._forensics_menu()
            elif choice == 4:
                self._misc_menu()
            elif choice == 5:
                break

    def _hash_tool_menu(self):
        items = [
            "Hash Crack",
            "Hash Identifier",
            "Multi Hash Crack",
        ]
        while True:
            print()
            menu = Menu(items, back=True)
            choice = menu.run()
            print()

            if choice is None:
                break
            elif choice == 0:
                self.hash.crack()
            elif choice == 1:
                self.hash_id.run()
            elif choice == 2:
                self.multi_hash.crack()

    def _cipher_tools_menu(self):
        items = [
            "Cipher Identifier",
            "Encoding",
            "Decoding",
            "Cipher Encrypt",
            "Cipher Decrypt",
        ]
        while True:
            print()
            menu = Menu(items, back=True)
            choice = menu.run()
            print()

            if choice is None:
                break
            elif choice == 0:
                self.cipher_id.run()
            elif choice == 1:
                if self.encdec.run(mode="encode"):
                    self.encdec.display_result()
            elif choice == 2:
                if self.encdec.run(mode="decode"):
                    self.encdec.display_result()
            elif choice == 3:
                if self.encdec.run(mode="cipher-encrypt"):
                    self.encdec.display_result()
            elif choice == 4:
                if self.encdec.run(mode="cipher-decrypt"):
                    self.encdec.display_result()

    def _stego_menu(self):
        items = [
            "LSB",
            "Metadata",
        ]
        while True:
            print()
            menu = Menu(items, back=True)
            choice = menu.run()
            print()

            if choice is None:
                break
            elif choice == 0:
                self.lsb.run()
            elif choice == 1:
                self.exif.run()

    def _forensics_menu(self):
        items = [
            "File Analyzer",
            "Hex Dump",
            "Strings Extractor",
        ]
        while True:
            print()
            menu = Menu(items, back=True)
            choice = menu.run()
            print()

            if choice is None:
                break
            elif choice == 0:
                self.file_analyzer.run()
            elif choice == 1:
                self.hex_dump.run()
            elif choice == 2:
                self.strings.run()

    def _misc_menu(self):
        items = [
            "Password Generator",
            "JWT Decode",
            "Number / Base Converter",
        ]
        while True:
            print()
            menu = Menu(items, back=True)
            choice = menu.run()
            print()

            if choice is None:
                break
            elif choice == 0:
                self.password_gen.run()
            elif choice == 1:
                self.jwt_decode.run()
            elif choice == 2:
                self.converter.run()

if __name__ == "__main__":
    try:
        PwnStarToolkit()
    except KeyboardInterrupt:
        print("\nGoodbye!")
