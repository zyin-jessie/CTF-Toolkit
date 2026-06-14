import secrets
import string

class PasswordGen:
    def run(self):
        print("\n=== Password Generator ===")

        try:
            length_str = input("Length (default 16): ").strip()
            length = int(length_str) if length_str else 16
        except ValueError:
            length = 16

        use_upper = input("Include uppercase? [Y/n]: ").strip().lower() != 'n'
        use_lower = input("Include lowercase? [Y/n]: ").strip().lower() != 'n'
        use_digits = input("Include digits? [Y/n]: ").strip().lower() != 'n'
        use_special = input("Include special chars? [y/N]: ").strip().lower() == 'y'
        count_str = input("How many passwords? (default 1): ").strip()
        try:
            count = int(count_str) if count_str else 1
        except ValueError:
            count = 1

        chars = ''
        if use_upper:
            chars += string.ascii_uppercase
        if use_lower:
            chars += string.ascii_lowercase
        if use_digits:
            chars += string.digits
        if use_special:
            chars += '!@#$%^&*()_+-=[]{}|;:,.<>?/~`'

        if not chars:
            print("At least one character set required.")
            return

        print()
        for i in range(count):
            pw = ''.join(secrets.choice(chars) for _ in range(length))
            print(f"  [{i+1}] {pw}")

    def get_result(self):
        return {'tool': 'Password Generator'}
