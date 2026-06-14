import re
import string

ENGLISH_FREQ = {
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
    'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
    'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
    'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
    'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974,
    'z': 0.074,
}

COMMON_WORDS = {
    'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all',
    'can', 'was', 'her', 'has', 'had', 'his', 'its', 'out',
    'did', 'get', 'may', 'new', 'now', 'old', 'see', 'way',
    'who', 'boy', 'she', 'two', 'how', 'our', 'say',
    'man', 'men', 'any', 'day', 'got', 'let', 'put', 'too',
    'use', 'own', 'ran', 'set', 'try', 'one', 'him',
    'this', 'that', 'with', 'from', 'have', 'what', 'when',
    'they', 'will', 'been', 'call', 'cold', 'come',
    'each', 'find', 'give', 'good', 'hand', 'here',
    'into', 'just', 'know', 'like', 'life', 'long', 'look',
    'made', 'make', 'many', 'more', 'much', 'must', 'name',
    'need', 'only', 'open', 'over', 'part', 'said', 'same',
    'some', 'such', 'take', 'tell', 'than', 'them', 'then',
    'time', 'well', 'went', 'word', 'work', 'year', 'love',
    'down', 'hello', 'world', 'flag', 'ctf', 'secret',
    'password', 'admin', 'root', 'user', 'test', 'hack',
    'pwn', 'cyber', 'security', 'encrypt', 'decode',
    'message', 'cipher', 'plain', 'text', 'data',
}

class CipherIdentifier:
    def run(self):
        print("\n=== Cipher / Encoding Detector ===")
        h = input("Enter text: ").strip()
        if not h:
            print("No input.")
            return
        ciphers = self._identify(h)
        if ciphers:
            print("\nPossible cipher / encoding:")
            for name, pct in ciphers:
                bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
                print(f"  {bar}  {pct:3d}%  {name}")
        else:
            print("\nNo known cipher or encoding matches this input.")

    @staticmethod
    def _freq_score(text):
        letters = [c.lower() for c in text if c.isalpha()]
        if not letters:
            return 0.0
        return sum(ENGLISH_FREQ.get(c, 0) for c in letters) / len(letters)

    @staticmethod
    def _english_score(text):
        letters = [c.lower() for c in text if c.isalpha()]
        if not letters:
            return 0.0
        freq_val = sum(ENGLISH_FREQ.get(c, 0) for c in letters) / len(letters)
        words = text.lower().split()
        common = sum(1 for w in words if w in COMMON_WORDS)
        word_bonus = common * 4.0
        return round(freq_val + word_bonus, 2)

    @staticmethod
    def _best_caesar_shift(text):
        best_score = 0.0
        best_shift = 0
        for shift in range(26):
            decoded = []
            for c in text:
                if 'a' <= c <= 'z':
                    decoded.append(chr((ord(c) - 97 + shift) % 26 + 97))
                elif 'A' <= c <= 'Z':
                    decoded.append(chr((ord(c) - 65 + shift) % 26 + 65))
                else:
                    decoded.append(c)
            score = CipherIdentifier._english_score(''.join(decoded))
            if score > best_score:
                best_score = score
                best_shift = shift
        return best_shift, best_score

    @staticmethod
    def _apply_rot13(text):
        result = []
        for c in text:
            if 'a' <= c <= 'z':
                result.append(chr((ord(c) - 97 + 13) % 26 + 97))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - 65 + 13) % 26 + 65))
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def _apply_rot47(text):
        result = []
        for c in text:
            if 33 <= ord(c) <= 126:
                result.append(chr(33 + (ord(c) - 33 + 47) % 94))
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def _identify(h):
        res = []
        add = lambda n, p: res.append((n, p))

        h_stripped = h.strip()
        h_lower = h_stripped.lower()

        is_letters_only = all(c.isalpha() or c.isspace() for c in h_stripped)
        is_upper = all(c in string.ascii_uppercase for c in h_stripped if c.isalpha())
        is_lower = all(c in string.ascii_lowercase for c in h_stripped if c.isalpha()) if any(c.isalpha() for c in h_stripped) else False
        is_digits_only = all(c.isdigit() or c.isspace() for c in h_stripped)
        blank = h_stripped == ''

        if blank:
            return res

        # ====== 1. Formats with distinctive prefixes/suffixes ======
        if h_stripped.startswith('<~') and h_stripped.endswith('~>'):
            add("Ascii85 (Adobe)", 95)

        parts_dot = h_stripped.split('.')
        if len(parts_dot) == 3 and all(p for p in parts_dot):
            if all(re.match(r'^[A-Za-z0-9\-_]+$', p) for p in parts_dot):
                add("JWT (JSON Web Token)", 95)

        if '%' in h_stripped and re.search(r'%[0-9a-fA-F]{2}', h_stripped):
            add("URL encoding", 95)

        qp_matches = re.findall(r'=[0-9a-fA-F]{2}', h_stripped)
        if len(qp_matches) >= 3:
            add("Quoted-printable", 90)
        elif len(qp_matches) >= 1 and re.search(r'(?:\r\n|\n)', h_stripped):
            add("Quoted-printable", 80)

        if re.search(r'\\u[0-9a-fA-F]{4}', h_stripped):
            add("Unicode escape (\\uXXXX)", 90)
        if re.search(r'\\U[0-9a-fA-F]{8}', h_stripped):
            add("Unicode escape (\\UXXXXXXXX)", 90)

        if '\\x' in h_stripped:
            add("Escaped hex string", 90)

        if h_stripped.startswith('xn--'):
            add("Punycode / IDN encoding", 85)

        # ====== 2. Constrained character-set formats ======
        if re.match(r'^[01\s]+$', h_stripped):
            add("Binary", 90)

        if re.match(r'^[.\- /]+$', h_stripped):
            add("Morse code", 85)

        if re.match(r'^[0-9a-fA-F]{2,}$', h_stripped) and len(h_stripped) % 2 == 0:
            try:
                decoded = bytes.fromhex(h_stripped)
                if all(32 <= b <= 126 or b in (10, 13) for b in decoded):
                    add("Hex", 95)
                elif len(h_stripped) in (32, 40, 48, 56, 64, 96, 128):
                    add("Hex", 92)
                elif any(b >= 128 for b in decoded):
                    add("Hex", 75)
                else:
                    add("Hex", 70)
            except Exception:
                pass

        if re.match(r'^[0-9a-fA-F\s]+$', h_stripped):
            spaced = h_stripped.replace(' ', '').replace('\t', '').replace('\n', '')
            if spaced and re.match(r'^[0-9a-fA-F]+$', spaced) and len(spaced) >= 4:
                has_af = any(c in 'abcdefABCDEF' for c in spaced)
                if has_af or len(spaced) < 6:
                    add("Hex (with spaces)", 75)

        stripped_bf = h_stripped.replace(' ', '').replace('\t', '').replace('\n', '')
        if stripped_bf and set(stripped_bf) <= {'+', '-', '<', '>', '[', ']', ',', '.'}:
            bf_chars = set(stripped_bf)
            if not bf_chars <= {'.', '-'}:
                add("Brainfuck", 90)

        if re.match(r'^(Ook[.?!]\s*)+$', h_stripped):
            add("Ook!", 85)

        # ====== 3. Letter-only ciphers (Baconian, Atbash, ROT13, Caesar) ======
        if is_letters_only and len(h_stripped) > 3:
            only_ab = set(h_stripped.replace(' ', '')) <= {'A', 'B'}
            if only_ab and len(h_stripped) >= 5:
                add("Baconian cipher", 95)
            elif is_upper and len(set(h_stripped.replace(' ', ''))) <= 2 and len(h_stripped) >= 5:
                add("Baconian cipher", 85)
            elif is_upper and len(h_stripped) < 50 and not only_ab:
                add("Baconian cipher", 55)

            if is_upper and len(set(h_stripped.replace(' ', ''))) >= 24:
                add("Atbash cipher", 40)

            rot13_result = CipherIdentifier._apply_rot13(h_stripped)
            orig_score = CipherIdentifier._english_score(h_stripped)
            rot13_score = CipherIdentifier._english_score(rot13_result)
            if rot13_score > 10.0 and rot13_score > orig_score * 1.3 and rot13_result != h_stripped:
                add("ROT13", 95)
            elif rot13_score > 8.0 and rot13_score > orig_score * 1.5 and rot13_result != h_stripped:
                add("ROT13", 80)

            best_shift, caesar_score = CipherIdentifier._best_caesar_shift(h_stripped)
            if caesar_score > 12.0:
                if best_shift == 0:
                    add("Plaintext / no Caesar shift", 60)
                elif best_shift == 13:
                    pass
                else:
                    add(f"Caesar (shift {best_shift})", 85)
            elif caesar_score > 8.0:
                if best_shift != 0 and best_shift != 13:
                    add(f"Caesar (shift {best_shift})", 65)
            elif caesar_score > 5.0:
                if best_shift != 0 and best_shift != 13:
                    add(f"Caesar (shift {best_shift})", 45)

            add("Substitution cipher", 30)
            if is_upper and len(set(h_stripped.replace(' ', ''))) >= 20:
                add("Simple substitution", 45)

        # ====== 4. Encoding formats (Base58/32/64/url/62) ======
        if re.match(r'^[1-9A-HJ-NP-Za-km-z]+$', h_stripped) and len(h_stripped) > 4:
            is_pure_hex = re.match(r'^[0-9a-fA-F]+$', h_stripped) and len(h_stripped) in (32, 40, 48, 56, 64, 96, 128)
            if not (h_stripped.isdigit() and len(h_stripped) <= 6) and not is_pure_hex:
                add("Base58", 75)

        if re.match(r'^[A-Z2-7]+=*$', h_stripped) and len(h_stripped) > 4:
            try:
                import base64
                raw = h_stripped
                pad = (8 - len(raw) % 8) % 8
                if pad:
                    raw += '=' * pad
                base64.b32decode(raw)
                add("Base32", 90)
            except Exception:
                if h_stripped.endswith('='):
                    add("Base32", 65)

        if re.match(r'^[A-Za-z0-9+/]*={0,2}$', h_stripped) and len(h_stripped) % 4 == 0 and len(h_stripped) > 4:
            # Skip strings that look like pure hex hashes
            is_pure_hex = re.match(r'^[0-9a-fA-F]+$', h_stripped) and len(h_stripped) in (32, 40, 48, 56, 64, 96, 128)
            if not is_pure_hex:
                try:
                    import base64
                    decoded = base64.b64decode(h_stripped)
                    if all(32 <= b <= 126 or b in (10, 13) for b in decoded):
                        add("Base64", 95)
                    else:
                        add("Base64", 85)
                except Exception:
                    if h_stripped.endswith('='):
                        add("Base64", 70)

        if re.match(r'^[A-Za-z0-9\-_]+$', h_stripped) and len(h_stripped) > 6:
            # Ensure it has at least one non-alpha char or is long enough
            has_special = any(c.isdigit() or c in '-_' for c in h_stripped)
            # Skip pure hex strings that look like hashes
            is_pure_hex = re.match(r'^[0-9a-fA-F]+$', h_stripped) and len(h_stripped) in (32, 40, 48, 56, 64, 96, 128)
            if (has_special or len(h_stripped) > 16) and not is_pure_hex:
                try:
                    import base64
                    padded = h_stripped + '=' * ((4 - len(h_stripped) % 4) % 4)
                    padded = padded.replace('-', '+').replace('_', '/')
                    decoded = base64.b64decode(padded)
                    if all(32 <= b <= 126 or b in (10, 13) for b in decoded):
                        add("Base64url", 90)
                    else:
                        add("Base64url", 75)
                except Exception:
                    pass

        # ====== 5. UUID ======
        if len(h_stripped) == 32 and all(c in '0123456789abcdef' for c in h_lower):
            add("UUID (no dashes)", 60)
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', h_lower):
            add("UUID", 99)

        if re.match(r'^[A-Za-z0-9]+$', h_stripped) and 4 < len(h_stripped) <= 20:
            add("Base62", 55)

        # ====== 6. ROT-based ciphers on non-alpha ======
        if is_digits_only and len(h_stripped) > 2:
            add("ROT5", 40)

        if not is_letters_only and len(h_stripped) > 3:
            try:
                rot47 = CipherIdentifier._apply_rot47(h_stripped)
                if rot47 != h_stripped:
                    score = CipherIdentifier._english_score(rot47)
                    if score > 12.0:
                        add("ROT47", 85)
                    elif score > 9.0:
                        add("ROT47", 70)
            except Exception:
                pass

        # ====== 7. Vigenere (index of coincidence) ======
        if is_letters_only and len(h_stripped) > 20:
            letter_list = [c.lower() for c in h_stripped if c.isalpha()]
            n = len(letter_list)
            if n > 20:
                freq = {}
                for c in letter_list:
                    freq[c] = freq.get(c, 0) + 1
                ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
                if 0.030 < ic < 0.055:
                    add("Vigenere / polyalphabetic cipher", 55)
                elif ic < 0.030 and n > 50:
                    add("Vigenere / polyalphabetic cipher", 70)

        return res

    def get_result(self):
        return {}
