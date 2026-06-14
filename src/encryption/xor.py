class XORCipher:
    def __init__(self):
        self.input_text = ""
        self.key = ""
        self.output_text = ""

    def run(self):
        print("\n=== XOR Cipher ===")
        print("[1] XOR Encrypt/Decrypt with key")
        print("[2] Single-byte XOR brute force")
        print("[0] Back")

        choice = input("Select operation: ").strip()

        if choice == '0':
            return
        elif choice == '1':
            self._xor_with_key()
        elif choice == '2':
            self._xor_bruteforce()
        else:
            print("Invalid option.")

    def _xor_with_key(self):
        self.input_text = input("Enter text: ")
        self.key = input("Enter key: ")

        if not self.key:
            print("Key cannot be empty.")
            return

        result = []
        key_len = len(self.key)
        for i, c in enumerate(self.input_text):
            result.append(chr(ord(c) ^ ord(self.key[i % key_len])))
        self.output_text = ''.join(result)

        print(f"\nResult: {self._repr_output(self.output_text)}")

    def _xor_bruteforce(self):
        self.input_text = input("Enter ciphertext (raw bytes not supported, use printable chars): ")

        print("\n=== Brute Force Results ===")
        found = []
        for key in range(256):
            decrypted = ''.join(chr(ord(c) ^ key) for c in self.input_text)
            if all(32 <= ord(ch) <= 126 or ch in '\n\r\t' for ch in decrypted):
                found.append((key, decrypted))
                printable_key = chr(key) if 32 <= key <= 126 else f"\\x{key:02x}"
                print(f"Key {key:3d} ({printable_key}): {decrypted}")

        if not found:
            print("No printable decryption found with any single-byte key.")

    @staticmethod
    def _repr_output(text):
        return ''.join(
            ch if 32 <= ord(ch) <= 126 else f"\\x{ord(ch):02x}"
            for ch in text
        )

    def get_result(self):
        return {
            'operation': 'XOR',
            'input': self.input_text,
            'key': self.key,
            'output': self.output_text
        }
