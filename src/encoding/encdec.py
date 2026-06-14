import base64
import urllib.parse
import binascii
import string
from utils.menu import Menu
from decryption.vigenere import Vigenere
from encryption.xor import XORCipher

class EncDec:
    def __init__(self):
        self.input_text = ""
        self.output_text = ""

    def run(self, mode="encode"):
        self.input_text = ""
        self.output_text = ""

        codec_ops = [
            ("Base64", self._base64_encode, "encode"),
            ("Base64", self._base64_decode, "decode"),
            ("Base32", self._base32_encode, "encode"),
            ("Base32", self._base32_decode, "decode"),
            ("Hex", self._hex_encode, "encode"),
            ("Hex", self._hex_decode, "decode"),
            ("URL", self._url_encode, "encode"),
            ("URL", self._url_decode, "decode"),
            ("Binary", self._binary_encode, "encode"),
            ("Binary", self._binary_decode, "decode"),
        ]

        cipher_encrypt_ops = [
            ("ROT13", self._rot13),
            ("ROT47", self._rot47),
            ("Caesar Cipher", self._caesar),
            ("Atbash Cipher", self._atbash),
            ("Reverse String", self._reverse),
            ("Text <-> ASCII Codes", self._ascii_convert),
            ("XOR Cipher", self._xor_run),
            ("Vigenere", self._vigenere_encrypt),
        ]

        cipher_decrypt_ops = [
            ("ROT13", self._rot13),
            ("ROT47", self._rot47),
            ("Caesar Cipher", self._caesar),
            ("Atbash Cipher", self._atbash),
            ("Reverse String", self._reverse),
            ("Text <-> ASCII Codes", self._ascii_convert),
            ("XOR Cipher", self._xor_run),
            ("Vigenere", self._vigenere_decrypt),
        ]

        if mode == "encode":
            filtered = [(n, fn) for n, fn, _ in codec_ops if _ == "encode"]
            title = "Encoding"
        elif mode == "decode":
            filtered = [(n, fn) for n, fn, _ in codec_ops if _ == "decode"]
            title = "Decoding"
        elif mode == "cipher-encrypt":
            filtered = cipher_encrypt_ops
            title = "Cipher Encrypt"
        else:
            filtered = cipher_decrypt_ops
            title = "Cipher Decrypt"

        print(f"\n=== {title} ===")

        menu_items = [name for name, _ in filtered]
        menu = Menu(menu_items, back=True)
        choice = menu.run()
        print()

        if choice is None:
            return False

        name, fn = filtered[choice]
        if name in ("XOR Cipher", "Vigenere"):
            fn()
            return False

        self.input_text = input("Enter text: ")
        fn()
        return True

    def _xor_run(self):
        XORCipher().run()

    def _vigenere_encrypt(self):
        Vigenere().encode()

    def _vigenere_decrypt(self):
        Vigenere().decode()

    def _base64_encode(self):
        try:
            self.output_text = base64.b64encode(self.input_text.encode()).decode()
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _base64_decode(self):
        try:
            self.output_text = base64.b64decode(self.input_text.encode()).decode()
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _base32_encode(self):
        try:
            self.output_text = base64.b32encode(self.input_text.encode()).decode()
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _base32_decode(self):
        try:
            self.output_text = base64.b32decode(self.input_text.encode()).decode()
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _hex_encode(self):
        try:
            self.output_text = self.input_text.encode().hex()
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _hex_decode(self):
        try:
            self.output_text = bytes.fromhex(self.input_text).decode()
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _url_encode(self):
        try:
            self.output_text = urllib.parse.quote(self.input_text)
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _url_decode(self):
        try:
            self.output_text = urllib.parse.unquote(self.input_text)
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _binary_encode(self):
        try:
            self.output_text = ' '.join(format(ord(c), '08b') for c in self.input_text)
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _binary_decode(self):
        try:
            binary_values = self.input_text.split()
            self.output_text = ''.join(chr(int(b, 2)) for b in binary_values)
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _rot13(self):
        try:
            self.output_text = self.input_text.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            ))
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _rot47(self):
        try:
            self.output_text = ''.join(
                chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c) <= 126 else c
                for c in self.input_text
            )
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _caesar(self):
        try:
            shift_input = input("Enter shift value (default 3): ").strip()
            shift = int(shift_input) if shift_input else 3

            result = []
            for c in self.input_text:
                if c.isupper():
                    result.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
                elif c.islower():
                    result.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
                else:
                    result.append(c)
            self.output_text = ''.join(result)
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _atbash(self):
        try:
            atbash_table = str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba'
            )
            self.output_text = self.input_text.translate(atbash_table)
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _reverse(self):
        try:
            self.output_text = self.input_text[::-1]
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _ascii_convert(self):
        try:
            print("\n[1] Text -> ASCII Codes")
            print("[2] ASCII Codes -> Text")
            sub_choice = input("Select direction: ").strip()

            if sub_choice == '1':
                self.output_text = ' '.join(str(ord(c)) for c in self.input_text)
            elif sub_choice == '2':
                codes = [int(x.strip()) for x in self.input_text.split() if x.strip()]
                self.output_text = ''.join(chr(c) for c in codes)
            else:
                self.output_text = "Invalid option."
        except Exception as e:
            self.output_text = f"Error: {e}"

    def display_result(self):
        print(f"\nResult: {self.output_text}")

    def get_result(self):
        return {
            'operation': 'encoding/decoding',
            'input': self.input_text,
            'output': self.output_text
        }
