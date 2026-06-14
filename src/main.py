#!/usr/bin/env python3.14
from utils.banner import Banner
from utils.menu import Menu
from decryption.hash_crack import HashCrack
from decryption.hash_identifier import HashIdentifier
from decryption.cipher_identifier import CipherIdentifier
from encoding.encdec import EncDec

class PwnStarToolkit:
    def __init__(self):
        self.banner = Banner()
        self.hash = HashCrack()
        self.hash_id = HashIdentifier()
        self.cipher_id = CipherIdentifier()
        self.encdec = EncDec()

        self.run()

    def run(self):
        menu_items = [
            "Hash Crack",
            "Hash Identifier",
            "Cipher Identifier",
            "Encoding",
            "Decoding",
            "Cipher Encrypt",
            "Cipher Decrypt",
            "Exit",
        ]

        while True:
            print()
            menu = Menu(menu_items)
            choice = menu.run()
            print()

            if choice == 0:
                self.hash.crack()
            elif choice == 1:
                self.hash_id.run()
            elif choice == 2:
                self.cipher_id.run()
            elif choice == 3:
                if self.encdec.run(mode="encode"):
                    self.encdec.display_result()
            elif choice == 4:
                if self.encdec.run(mode="decode"):
                    self.encdec.display_result()
            elif choice == 5:
                if self.encdec.run(mode="cipher-encrypt"):
                    self.encdec.display_result()
            elif choice == 6:
                if self.encdec.run(mode="cipher-decrypt"):
                    self.encdec.display_result()
            elif choice == 7:
                break

if __name__ == "__main__":
    try:
        PwnStarToolkit()
    except KeyboardInterrupt:
        print("\nGoodbye!")
