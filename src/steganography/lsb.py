from PIL import Image
import numpy as np
import os
from utils.menu import Menu

class LSBSteg:
    def run(self):
        print("\n=== LSB Image Steganography ===")
        items = ["Encode", "Decode"]
        menu = Menu(items)
        choice = menu.run()
        print()

        if choice == 0:
            self._encode()
        elif choice == 1:
            self._decode()

    def _encode(self):
        path = input("Cover image path: ").strip()
        if not os.path.exists(path):
            print("File not found.")
            return
        msg = input("Secret message: ")
        password = input("XOR key (optional, leave blank for none): ").strip()

        if password:
            msg = self._xor_encrypt(msg, password)

        msg += "\x00\x00\x00"
        bits = ''.join(format(ord(c), '08b') for c in msg)

        img = Image.open(path).convert("RGB")
        arr = np.array(img)
        flat = arr.flatten()

        if len(bits) > len(flat):
            print("Message too long for this image.")
            return

        for i, bit in enumerate(bits):
            flat[i] = (flat[i] & 0xFE) | int(bit)

        out = flat.reshape(arr.shape)
        out_path = input("Output image path (default: stego_output.png): ").strip() or "stego_output.png"
        Image.fromarray(out).save(out_path)
        print(f"Saved to {out_path}")

    def _decode(self):
        path = input("Stego image path: ").strip()
        if not os.path.exists(path):
            print("File not found.")
            return

        img = Image.open(path).convert("RGB")
        arr = np.array(img)
        flat = arr.flatten()

        bits = ''.join(str(p & 1) for p in flat)
        chars = []
        for i in range(0, len(bits), 8):
            byte = bits[i:i+8]
            if len(byte) < 8:
                break
            c = chr(int(byte, 2))
            if c == "\x00":
                term = chars[-1:] == ["\x00"]
                chars = chars[:-1]
                break
            chars.append(c)

        msg = ''.join(chars)
        password = input("XOR key (if used during encoding, else blank): ").strip()
        if password:
            msg = self._xor_encrypt(msg, password)

        print(f"\nExtracted message: {msg}")

    @staticmethod
    def _xor_encrypt(text, key):
        return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))

    def get_result(self):
        return {'tool': 'LSB Steganography'}
