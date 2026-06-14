#!/usr/bin/env python3.14
from utils.banner import Banner
from utils.menu import Menu
from decryption.hash_crack import HashCrack
from decryption.hash_identifier import HashIdentifier
from decryption.cipher_identifier import CipherIdentifier
from decryption.vigenere import Vigenere
from encoding.encdec import EncDec
from encryption.xor import XORCipher

class PwnStarToolkit:
    def __init__(self):
        self.banner = Banner()
        self.hash = HashCrack()
        self.hash_id = HashIdentifier()
        self.cipher_id = CipherIdentifier()
        self.vigenere = Vigenere()
        self.encdec = EncDec()
        self.xor = XORCipher()

        self.run()

    def run(self):
        menu_items = [
            "Hash Crack",
            "Hash Identifier",
            "Cipher Identifier",
            "Vigenere Decode",
            "Encoding",
            "Decoding",
            "XOR Cipher",
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
                self.vigenere.decode()
            elif choice == 4:
                if self.encdec.run(mode="encode"):
                    self.encdec.display_result()
            elif choice == 5:
                if self.encdec.run(mode="decode"):
                    self.encdec.display_result()
            elif choice == 6:
                self.xor.run()
            elif choice == 7:
                break

if __name__ == "__main__":
    try:
        PwnStarToolkit()
    except KeyboardInterrupt:
        print("\nGoodbye!")
