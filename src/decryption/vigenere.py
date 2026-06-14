class Vigenere:
    def __init__(self):
        self.input_text = ""
        self.key = ""
        self.output_text = ""

    def encode(self):
        print("\n=== Vigenere Encrypt ===")

        self.input_text = input("Enter plaintext: ")
        self.key = input("Enter key: ").upper()

        self._perform_encryption()
        print(f"Encrypted text: {self.output_text}")

    def decode(self):
        print("\n=== Vigenere Decrypt ===")

        self.input_text = input("Enter ciphertext: ")
        self.key = input("Enter key: ").upper()

        self._perform_decryption()
        print(f"Decrypted text: {self.output_text}")

    def _perform_encryption(self):
        result = []
        key_index = 0

        for char in self.input_text:
            if char.isalpha():
                shift = ord(self.key[key_index % len(self.key)]) - ord('A')
                if char.isupper():
                    result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
                else:
                    result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
                key_index += 1
            else:
                result.append(char)

        self.output_text = ''.join(result)

    def _perform_decryption(self):
        result = []
        key_index = 0

        for char in self.input_text:
            if char.isalpha():
                shift = ord(self.key[key_index % len(self.key)]) - ord('A')
                if char.isupper():
                    result.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
                else:
                    result.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
                key_index += 1
            else:
                result.append(char)

        self.output_text = ''.join(result)

    def get_result(self):
        return {
            'input': self.input_text,
            'key': self.key,
            'output': self.output_text
        }