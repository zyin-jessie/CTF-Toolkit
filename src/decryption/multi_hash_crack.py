from utils.payload import Payload
from utils.menu import Menu
import hashlib
import os

try:
    hashlib.new('md4', b'test')
    _NTLM_SUPPORTED = True
except ValueError:
    _NTLM_SUPPORTED = False

class MultiHashCrack:
    def __init__(self):
        self.payload_loader = Payload()
        self.target_hash = ""
        self.hash_type = ""
        self.selected_payload = ""
        self.found_password = None

    def crack(self):
        print("\n=== Multi-Algorithm Hash Crack ===")
        hash_types = ["MD5", "SHA-1", "SHA-256"]
        hash_map = ['md5', 'sha1', 'sha256']
        if _NTLM_SUPPORTED:
            hash_types.append("NTLM")
            hash_map.append('ntlm')
        menu = Menu(hash_types)
        choice = menu.run()
        print()
        if choice is None:
            return
        self.hash_type = hash_map[choice]

        self.target_hash = input("Enter hash: ").strip().lower()

        payloads = self.payload_loader.find_payloads()
        if not payloads:
            print("No payload found.")
            return

        self._select_payload(payloads)
        self._execute_cracking()
        self._display_result()

    def _select_payload(self, payloads):
        print("\nAvailable payloads:")
        for i, payload_path in enumerate(payloads, 1):
            print(f"[{i}] {os.path.basename(payload_path)}")

        while True:
            try:
                choice = input("\nSelect payload: ").strip()
                if not choice:
                    self.selected_payload = payloads[0]
                    break

                choice_num = int(choice)
                if 1 <= choice_num <= len(payloads):
                    self.selected_payload = payloads[choice_num - 1]
                    break
                else:
                    print(f"Please enter a number between 1 and {len(payloads)}")
            except ValueError:
                print("Please enter a valid number")

        print(f"Payload: {os.path.basename(self.selected_payload)}")

    def _execute_cracking(self):
        print("Cracking... This may take a while.")

        try:
            with open(self.selected_payload, "r", encoding="latin-1") as file:
                for line in file:
                    password = line.rstrip("\n\r")
                    hashed = self._hash_password(password)

                    if hashed == self.target_hash:
                        self.found_password = password
                        break

        except FileNotFoundError:
            print(f"No available payload: {self.selected_payload}")
        except Exception as e:
            print(f"Error reading payload: {e}")

    def _hash_password(self, password):
        if self.hash_type == 'md5':
            return hashlib.md5(password.encode()).hexdigest()
        elif self.hash_type == 'sha1':
            return hashlib.sha1(password.encode()).hexdigest()
        elif self.hash_type == 'sha256':
            return hashlib.sha256(password.encode()).hexdigest()
        elif self.hash_type == 'ntlm':
            if _NTLM_SUPPORTED:
                return hashlib.new('md4', password.encode('utf-16le')).hexdigest()
        return ""

    def _display_result(self):
        if self.found_password:
            check_icon = self._colored_text("✓", "92")
            print(f"\n{check_icon} Password found: {self.found_password}")
        else:
            cross_icon = self._colored_text("✗", "91")
            print(f"\n{cross_icon} No password found in the payload.")

    @staticmethod
    def _colored_text(text, color_code):
        return f"\033[{color_code}m{text}\033[0m"

    def get_result(self):
        return {
            'success': self.found_password is not None,
            'hash_type': self.hash_type,
            'password': self.found_password,
            'target_hash': self.target_hash,
            'payload_used': self.selected_payload
        }
