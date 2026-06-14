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
            ("Base85", self._base85_encode, "encode"),
            ("Base85", self._base85_decode, "decode"),
            ("Base58", self._base58_encode, "encode"),
            ("Base58", self._base58_decode, "decode"),
            ("Hex", self._hex_encode, "encode"),
            ("Hex", self._hex_decode, "decode"),
            ("URL", self._url_encode, "encode"),
            ("URL", self._url_decode, "decode"),
            ("Binary", self._binary_encode, "encode"),
            ("Binary", self._binary_decode, "decode"),
            ("Morse", self._morse_encode, "encode"),
            ("Morse", self._morse_decode, "decode"),
        ]

        cipher_encrypt_ops = [
            ("ROT13", self._rot13),
            ("ROT47", self._rot47),
            ("Caesar", self._caesar),
            ("Atbash", self._atbash),
            ("Affine", self._affine),
            ("Rail Fence", self._rail_fence),
            ("Reverse", self._reverse),
            ("ASCII Conv", self._ascii_convert),
            ("XOR", self._xor_run),
            ("Vigenere", self._vigenere_encrypt),
        ]

        cipher_decrypt_ops = [
            ("ROT13", self._rot13),
            ("ROT47", self._rot47),
            ("Caesar", self._caesar),
            ("Atbash", self._atbash),
            ("Affine", self._affine_decrypt),
            ("Rail Fence", self._rail_fence_decrypt),
            ("Reverse", self._reverse),
            ("ASCII Conv", self._ascii_convert),
            ("XOR", self._xor_run),
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
            items = ["Text -> ASCII Codes", "ASCII Codes -> Text"]
            menu = Menu(items)
            sub_choice = menu.run()
            print()

            if sub_choice == 0:
                self.output_text = ' '.join(str(ord(c)) for c in self.input_text)
            elif sub_choice == 1:
                codes = [int(x.strip()) for x in self.input_text.split() if x.strip()]
                self.output_text = ''.join(chr(c) for c in codes)
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

    def _base85_encode(self):
        try:
            self.output_text = base64.b85encode(self.input_text.encode()).decode()
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _base85_decode(self):
        try:
            self.output_text = base64.b85decode(self.input_text.encode()).decode()
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _base58_encode(self):
        try:
            b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
            num = int.from_bytes(self.input_text.encode(), 'big')
            res = ''
            while num > 0:
                num, rem = divmod(num, 58)
                res = b58[rem] + res
            self.output_text = res or '1'
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _base58_decode(self):
        try:
            b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
            num = 0
            for c in self.input_text.strip():
                num = num * 58 + b58.index(c)
            byte_len = (num.bit_length() + 7) // 8
            self.output_text = num.to_bytes(byte_len, 'big').decode()
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _morse_encode(self):
        morse = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
            'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
            'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
            'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
            'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
            'Z': '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--',
            '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
            '9': '----.', '.': '.-.-.-', ',': '--..--', '?': '..--..',
            "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.',
            ')': '-.--.-', '&': '.-...', ':': '---...', ';': '-.-.-.',
            '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-',
            '"': '.-..-.', '$': '...-..-', '@': '.--.-.', ' ': '/',
        }
        try:
            words = []
            for c in self.input_text.upper():
                if c in morse:
                    words.append(morse[c])
            self.output_text = ' '.join(words)
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _morse_decode(self):
        reverse = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
            '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
            '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?',
            '.----.': "'", '-.-.--': '!', '-..-.': '/', '-.--.': '(',
            '-.--.-': ')', '.-...': '&', '---...': ':', '-.-.-.': ';',
            '-...-': '=', '.-.-.': '+', '-....-': '-', '..--.-': '_',
            '.-..-.': '"', '...-..-': '$', '.--.-.': '@',
        }
        try:
            words = []
            for token in self.input_text.strip().split(' '):
                if token == '/':
                    words.append(' ')
                elif token in reverse:
                    words.append(reverse[token])
            self.output_text = ''.join(words)
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _affine(self):
        try:
            a_s = input("Enter multiplier (a, must be coprime to 26, default 5): ").strip()
            a = int(a_s) if a_s else 5
            b_s = input("Enter shift (b, default 8): ").strip()
            b = int(b_s) if b_s else 8

            import math
            if math.gcd(a, 26) != 1:
                self.output_text = "Error: 'a' must be coprime to 26 (e.g., 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)"
                return

            a_inv = pow(a, -1, 26)
            result = []
            for c in self.input_text:
                if c.isupper():
                    enc = (a * (ord(c) - ord('A')) + b) % 26
                    result.append(chr(enc + ord('A')))
                elif c.islower():
                    enc = (a * (ord(c) - ord('a')) + b) % 26
                    result.append(chr(enc + ord('a')))
                else:
                    result.append(c)
            self.output_text = ''.join(result)
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _rail_fence(self):
        try:
            rails_s = input("Enter number of rails (default 3): ").strip()
            rails = int(rails_s) if rails_s else 3
            if rails < 2:
                self.output_text = "Error: need at least 2 rails"
                return

            fence = [[] for _ in range(rails)]
            rail = 0
            direction = 1
            for c in self.input_text:
                fence[rail].append(c)
                rail += direction
                if rail == rails - 1 or rail == 0:
                    direction *= -1
            self.output_text = ''.join(''.join(r) for r in fence)
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _affine_decrypt(self):
        try:
            a_s = input("Enter multiplier (a, must be coprime to 26, default 5): ").strip()
            a = int(a_s) if a_s else 5
            b_s = input("Enter shift (b, default 8): ").strip()
            b = int(b_s) if b_s else 8

            import math
            if math.gcd(a, 26) != 1:
                self.output_text = "Error: 'a' must be coprime to 26"
                return

            a_inv = pow(a, -1, 26)
            result = []
            for c in self.input_text:
                if c.isupper():
                    dec = (a_inv * ((ord(c) - ord('A')) - b)) % 26
                    result.append(chr(dec + ord('A')))
                elif c.islower():
                    dec = (a_inv * ((ord(c) - ord('a')) - b)) % 26
                    result.append(chr(dec + ord('a')))
                else:
                    result.append(c)
            self.output_text = ''.join(result)
        except Exception as e:
            self.output_text = f"Error: {e}"

    def _rail_fence_decrypt(self):
        try:
            rails_s = input("Enter number of rails (default 3): ").strip()
            rails = int(rails_s) if rails_s else 3
            if rails < 2:
                self.output_text = "Error: need at least 2 rails"
                return

            n = len(self.input_text)
            fence = [[''] * n for _ in range(rails)]
            rail = 0
            direction = 1
            for col in range(n):
                fence[rail][col] = '*'
                rail += direction
                if rail == rails - 1 or rail == 0:
                    direction *= -1

            idx = 0
            for r in range(rails):
                for c in range(n):
                    if fence[r][c] == '*':
                        fence[r][c] = self.input_text[idx]
                        idx += 1

            result = []
            rail = 0
            direction = 1
            for col in range(n):
                result.append(fence[rail][col])
                rail += direction
                if rail == rails - 1 or rail == 0:
                    direction *= -1
            self.output_text = ''.join(result)
        except Exception as e:
            self.output_text = f"Error: {e}"
