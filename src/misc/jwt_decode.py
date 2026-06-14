import base64
import json
import sys

class JWTDecode:
    def run(self):
        print("\n=== JWT Decode ===")
        token = input("JWT token: ").strip()

        parts = token.split('.')
        if len(parts) != 3:
            print("Invalid JWT: expected 3 dot-separated segments.")
            return

        try:
            header_b64 = self._pad(parts[0])
            payload_b64 = self._pad(parts[1])
            sig_b64 = parts[2]

            header = json.loads(base64.urlsafe_b64decode(header_b64).decode())
            payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())

            print(f"\n\033[1mHeader:\033[0m")
            print(json.dumps(header, indent=2))

            print(f"\n\033[1mPayload:\033[0m")
            print(json.dumps(payload, indent=2))

            print(f"\n\033[1mSignature (raw):\033[0m {sig_b64[:32]}...")
            print(f"\033[1mAlgorithm:\033[0m {header.get('alg', 'unknown')}")

            if header.get('alg', '').lower() == 'none':
                print("\033[93m[!] alg=none detected! Try forging tokens.\033[0m")

        except Exception as e:
            print(f"Decode error: {e}")

    @staticmethod
    def _pad(s):
        return s + '=' * (4 - len(s) % 4) if len(s) % 4 else s

    def get_result(self):
        return {'tool': 'JWT Decode'}
