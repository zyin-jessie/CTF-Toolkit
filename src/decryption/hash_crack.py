from utils.payload import Payload
from utils.menu import Menu
import hashlib
import hmac
import os
import base64

try:
    import crypt as _crypt
    _HAS_CRYPT = True
except ImportError:
    _HAS_CRYPT = False

try:
    hashlib.new('md4', b'test')
    _HAS_MD4 = True
except ValueError:
    _HAS_MD4 = False


def _md4(data):
    if _HAS_MD4:
        return hashlib.new('md4', data)
    def _l(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    def _f(x, y, z): return (x & y) | (~x & z)
    def _g(x, y, z): return (x & y) | (x & z) | (y & z)
    def _h(x, y, z): return x ^ y ^ z
    r1 = [3, 7, 11, 19] * 4
    r2 = [3, 5, 9, 13] * 4
    r3 = [3, 9, 11, 15] * 4
    w2 = [(j * 4 + j) % 16 for j in range(16)]
    w2 = [(j * 4 + j // 4) % 16 for j in range(16)]
    w2 = [(0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)[j] for j in range(16)]
    w3 = [(0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)[j] for j in range(16)]
    orig_len = len(data)
    data = data + b'\x80'
    while len(data) % 64 != 56:
        data += b'\x00'
    data += (orig_len * 8).to_bytes(8, 'little')
    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for i in range(0, len(data), 64):
        w = [int.from_bytes(data[i + j * 4:i + (j + 1) * 4], 'little') for j in range(16)]
        a, b, c, d = A, B, C, D
        for j in range(16):
            t = (a + _f(b, c, d) + w[j]) & 0xFFFFFFFF
            a, b, c, d = d, _l(t, r1[j]), b, c
        for j in range(16):
            t = (a + _g(b, c, d) + w[w2[j]] + 0x5A827999) & 0xFFFFFFFF
            a, b, c, d = d, _l(t, r2[j]), b, c
        for j in range(16):
            t = (a + _h(b, c, d) + w[w3[j]] + 0x6ED9EBA1) & 0xFFFFFFFF
            a, b, c, d = d, _l(t, r3[j]), b, c
        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF
    return (A.to_bytes(4, 'little') + B.to_bytes(4, 'little') +
            C.to_bytes(4, 'little') + D.to_bytes(4, 'little'))


def _make_blake2b(size):
    def f(pw, target, extra):
        return hashlib.blake2b(pw.encode(), digest_size=size // 8).hexdigest() == target
    return f


def _make_blake2s(size):
    def f(pw, target, extra):
        return hashlib.blake2s(pw.encode(), digest_size=size // 8).hexdigest() == target
    return f


def _make_hmac(algo):
    def f(pw, target, extra):
        return hmac.new(extra['key'].encode(), pw.encode(), algo).hexdigest() == target
    return f


def _make_pbkdf2(algo):
    def f(pw, target, extra):
        dk = hashlib.pbkdf2_hmac(algo, pw.encode(), extra['salt'].encode(), extra['rounds'])
        return dk.hex() == target
    return f


class HashCrack:
    def __init__(self):
        self.payload_loader = Payload()
        self.target = ""
        self.extra = {}
        self.hash_type = ""
        self.selected_payload = ""
        self.found_password = None
        self.verify_func = None

    def crack(self):
        self.found_password = None
        print("\n=== Hash Crack ===")

        cat = self._pick_category()
        if cat is None:
            return

        ht = self._pick_hash_type(cat)
        if ht is None:
            return

        if ht.get('unavailable'):
            print(f"\n\033[93mNotice: {ht['unavailable']}\033[0m")
            return

        self.hash_type = ht['name']
        self.verify_func = ht['verify']
        self.extra = {}

        if ht.get('need_salt') and ht.get('salt_prompt'):
            self.extra['salt'] = input(ht['salt_prompt']).strip()

        if ht.get('need_key'):
            self.extra['key'] = input("Enter key: ").strip()

        if ht.get('need_rounds'):
            r = input("Enter iterations (default 1000): ").strip()
            self.extra['rounds'] = int(r) if r else 1000

        if ht.get('need_username'):
            self.extra['username'] = input("Enter username: ").strip()

        self.target = input("Enter hash: ").strip().lower()

        payloads = self.payload_loader.find_payloads()
        if not payloads:
            print("No payload found.")
            return

        self._select_payload(payloads)
        self._execute_cracking()
        self._display_result()

    def _pick_category(self):
        cats = [
            "Raw Hashes (MD4, MD5, SHA*, Keccak, Blake2)",
            "Crypt-Based (descrypt, md5crypt, sha*crypt, SunMD5)",
            "HMAC / PBKDF2",
            "Windows (NT, NetNTLM, MSCHAPv2)",
            "Database (MySQL, MSSQL, PostgreSQL, Oracle)",
            "Enterprise / Web (Django, PHPS, tacacs)",
            "Other (plaintext, AIX SSHA512, etc.)",
        ]
        menu = Menu(cats)
        choice = menu.run()
        print()
        return choice

    def _pick_hash_type(self, category):
        groups = self._build_groups()
        if category >= len(groups):
            return None
        group = groups[category]
        items = [h['name'] for h in group]
        menu = Menu(items)
        choice = menu.run()
        print()
        return group[choice]

    def _build_groups(self):
        raw = [
            self._ht("Raw-MD4", self._v_md4),
            self._ht("Raw-MD5", self._v_md5),
            self._ht("Raw-MD5u", self._v_md5),
            self._ht("Raw-SHA1", self._v_sha1),
            self._ht("Raw-SHA224", self._v_sha224),
            self._ht("Raw-SHA256", self._v_sha256),
            self._ht("Raw-SHA384", self._v_sha384),
            self._ht("Raw-SHA512", self._v_sha512),
            self._ht("Raw-SHA3-224", self._v_sha3_224),
            self._ht("Raw-SHA3-256", self._v_sha3_256),
            self._ht("Raw-SHA3-384", self._v_sha3_384),
            self._ht("Raw-SHA3-512", self._v_sha3_512),
            self._ht("Raw-Keccak-256", self._v_keccak_256),
            self._ht("Raw-Keccak-512", self._v_keccak_512),
            self._ht("Raw-Blake2b-160", self._v_blake2b_160),
            self._ht("Raw-Blake2b-256", self._v_blake2b_256),
            self._ht("Raw-Blake2b-384", self._v_blake2b_384),
            self._ht("Raw-Blake2b-512", self._v_blake2b_512),
            self._ht("Raw-Blake2s-128", self._v_blake2s_128),
            self._ht("Raw-Blake2s-160", self._v_blake2s_160),
            self._ht("Raw-Blake2s-224", self._v_blake2s_224),
            self._ht("Raw-Blake2s-256", self._v_blake2s_256),
        ]

        if not _HAS_CRYPT:
            crypt_msg = "crypt module not available in Python 3.13+"
            crypt_based = [
                self._ht("descrypt (DES)", None, unavailable=crypt_msg),
                self._ht("bsdicrypt", None, unavailable=crypt_msg),
                self._ht("md5crypt ($1$)", None, unavailable=crypt_msg),
                self._ht("sha256crypt ($5$)", None, unavailable=crypt_msg),
                self._ht("sha512crypt ($6$)", None, unavailable=crypt_msg),
                self._ht("SunMD5 ($md5$)", None, unavailable=crypt_msg),
            ]
        else:
            crypt_based = [
                self._ht("descrypt (DES)", self._v_crypt),
                self._ht("bsdicrypt", self._v_crypt),
                self._ht("md5crypt ($1$)", self._v_crypt),
                self._ht("sha256crypt ($5$)", self._v_crypt),
                self._ht("sha512crypt ($6$)", self._v_crypt),
                self._ht("SunMD5 ($md5$)", self._v_crypt),
            ]
        crypt_based.append(
            self._ht("AIX SSHA512", self._v_aix_ssha512,
                     need_salt=True, salt_prompt="Enter salt: "),
        )

        hmac_pbkdf2 = [
            self._ht("HMAC-MD5", self._v_hmac_md5, need_key=True),
            self._ht("HMAC-SHA1", self._v_hmac_sha1, need_key=True),
            self._ht("HMAC-SHA224", self._v_hmac_sha224, need_key=True),
            self._ht("HMAC-SHA256", self._v_hmac_sha256, need_key=True),
            self._ht("PBKDF2-HMAC-MD4", self._v_pbkdf2_md4,
                     need_salt=True, need_rounds=True, salt_prompt="Enter salt: "),
            self._ht("PBKDF2-HMAC-MD5", self._v_pbkdf2_md5,
                     need_salt=True, need_rounds=True, salt_prompt="Enter salt: "),
            self._ht("PBKDF2-HMAC-SHA1", self._v_pbkdf2_sha1,
                     need_salt=True, need_rounds=True, salt_prompt="Enter salt: "),
            self._ht("PBKDF2-HMAC-SHA256", self._v_pbkdf2_sha256,
                     need_salt=True, need_rounds=True, salt_prompt="Enter salt: "),
        ]

        windows = [
            self._ht("NT (NTLM)", self._v_ntlm),
            self._ht("NetNTLMv2", self._v_netntlmv2,
                     need_salt=True, salt_prompt="Enter server challenge (hex): "),
            self._ht("MSCHAPv2 (naive)", self._v_mschapv2_naive,
                     need_salt=True, salt_prompt="Enter challenge (hex): "),
        ]

        database = [
            self._ht("mysql (MySQL 3.21-4.0)", self._v_mysql_old),
            self._ht("mysql-sha1 (MySQL 4.1+)", self._v_mysql_sha1),
            self._ht("mssql (old)", self._v_mssql),
            self._ht("mssql05", self._v_mssql05),
            self._ht("mssql12", self._v_mssql12),
            self._ht("postgres (MD5)", self._v_postgres, need_username=True),
            self._ht("Oracle o10glogon", self._v_oracle_o10g),
        ]

        enterprise = [
            self._ht("Django (PBKDF2-SHA256)", self._v_django),
            self._ht("PHPS2 (phpBB3)", self._v_phps2),
            self._ht("tacacs-plus", self._v_tacacs,
                     need_salt=True, salt_prompt="Enter challenge/connection id (hex): "),
        ]

        other = [
            self._ht("plaintext", self._v_plaintext),
            self._ht("ASA-MD5 (Cisco)", self._v_asa_md5,
                     need_salt=True, salt_prompt="Enter salt: "),
            self._ht("SybaseASE", self._v_sybase_ase),
        ]

        return [raw, crypt_based, hmac_pbkdf2, windows, database, enterprise, other]

    @staticmethod
    def _ht(name, verify, need_salt=False, salt_prompt="", need_key=False,
            need_rounds=False, need_username=False, unavailable=None):
        return {
            'name': name,
            'verify': verify,
            'need_salt': need_salt,
            'salt_prompt': salt_prompt,
            'need_key': need_key,
            'need_rounds': need_rounds,
            'need_username': need_username,
            'unavailable': unavailable,
        }

    def _select_payload(self, payloads):
        def count_lines(path):
            try:
                with open(path, 'r', encoding='latin-1') as f:
                    return sum(1 for _ in f)
            except Exception:
                return 0
        items = [f"{os.path.basename(p)}  ({count_lines(p):,})" for p in payloads]
        menu = Menu(items)
        choice = menu.run()
        print()
        self.selected_payload = payloads[choice]
        print(f"Payload: {os.path.basename(self.selected_payload)}")

    def _execute_cracking(self):
        print("Cracking... This may take a while.")
        try:
            with open(self.selected_payload, "r", encoding="latin-1") as f:
                for i, line in enumerate(f, 1):
                    pw = line.rstrip("\n\r")
                    if not pw:
                        continue
                    try:
                        if self.verify_func(pw, self.target, self.extra):
                            self.found_password = pw
                            break
                    except Exception:
                        continue
                    if i % 500000 == 0:
                        print(f"  Processed {i:,} lines...")
        except FileNotFoundError:
            print(f"No available payload: {self.selected_payload}")
        except Exception as e:
            print(f"Error: {e}")

    def _display_result(self):
        if self.found_password:
            print(f"\n\033[92m\u2713\033[0m Password found: {self.found_password}")
        else:
            print(f"\n\033[91m\u2717\033[0m No password found in the payload.")

    # ------- verify functions -------

    @staticmethod
    def _v_md4(pw, target, extra):
        return _md4(pw.encode()).hex() == target

    @staticmethod
    def _v_md5(pw, target, extra):
        return hashlib.md5(pw.encode()).hexdigest() == target

    @staticmethod
    def _v_sha1(pw, target, extra):
        return hashlib.sha1(pw.encode()).hexdigest() == target

    @staticmethod
    def _v_sha224(pw, target, extra):
        return hashlib.sha224(pw.encode()).hexdigest() == target

    @staticmethod
    def _v_sha256(pw, target, extra):
        return hashlib.sha256(pw.encode()).hexdigest() == target

    @staticmethod
    def _v_sha384(pw, target, extra):
        return hashlib.sha384(pw.encode()).hexdigest() == target

    @staticmethod
    def _v_sha512(pw, target, extra):
        return hashlib.sha512(pw.encode()).hexdigest() == target

    @staticmethod
    def _v_sha3_224(pw, target, extra):
        return hashlib.sha3_224(pw.encode()).hexdigest() == target

    @staticmethod
    def _v_sha3_256(pw, target, extra):
        return hashlib.sha3_256(pw.encode()).hexdigest() == target

    @staticmethod
    def _v_sha3_384(pw, target, extra):
        return hashlib.sha3_384(pw.encode()).hexdigest() == target

    @staticmethod
    def _v_sha3_512(pw, target, extra):
        return hashlib.sha3_512(pw.encode()).hexdigest() == target

    @staticmethod
    def _v_keccak_256(pw, target, extra):
        return hashlib.sha3_256(pw.encode()).hexdigest() == target

    @staticmethod
    def _v_keccak_512(pw, target, extra):
        return hashlib.sha3_512(pw.encode()).hexdigest() == target

    _v_blake2b_160 = staticmethod(_make_blake2b(160))
    _v_blake2b_256 = staticmethod(_make_blake2b(256))
    _v_blake2b_384 = staticmethod(_make_blake2b(384))
    _v_blake2b_512 = staticmethod(_make_blake2b(512))
    _v_blake2s_128 = staticmethod(_make_blake2s(128))
    _v_blake2s_160 = staticmethod(_make_blake2s(160))
    _v_blake2s_224 = staticmethod(_make_blake2s(224))
    _v_blake2s_256 = staticmethod(_make_blake2s(256))

    @staticmethod
    def _v_crypt(pw, target, extra):
        return _crypt.crypt(pw, target) == target

    @staticmethod
    def _v_aix_ssha512(pw, target, extra):
        if 'salt' not in extra or not extra['salt']:
            return False
        h = hashlib.sha512(pw.encode() + extra['salt'].encode()).digest()
        return base64.b64encode(h + extra['salt'].encode()).decode() == target

    _v_hmac_md5 = staticmethod(_make_hmac('md5'))
    _v_hmac_sha1 = staticmethod(_make_hmac('sha1'))
    _v_hmac_sha224 = staticmethod(_make_hmac('sha224'))
    _v_hmac_sha256 = staticmethod(_make_hmac('sha256'))

    _v_pbkdf2_md4 = staticmethod(_make_pbkdf2('md4'))
    _v_pbkdf2_md5 = staticmethod(_make_pbkdf2('md5'))
    _v_pbkdf2_sha1 = staticmethod(_make_pbkdf2('sha1'))
    _v_pbkdf2_sha256 = staticmethod(_make_pbkdf2('sha256'))

    @staticmethod
    def _v_ntlm(pw, target, extra):
        return _md4(pw.encode('utf-16le')).hex() == target

    @staticmethod
    def _v_netntlmv2(pw, target, extra):
        try:
            ntlm = _md4(pw.encode('utf-16le'))
            chal = bytes.fromhex(extra.get('salt', ''))
            return hmac.new(ntlm, chal, 'md5').hexdigest() == target
        except Exception:
            return False

    @staticmethod
    def _v_mschapv2_naive(pw, target, extra):
        try:
            ntlm = _md4(pw.encode('utf-16le'))
            chal = bytes.fromhex(extra.get('salt', ''))
            return hashlib.md5(ntlm + chal).hexdigest() == target
        except Exception:
            return False

    @staticmethod
    def _v_mysql_old(pw, target, extra):
        nr = 1345345333
        add = 7
        nr2 = 0x12345671
        for c in pw.encode():
            if c in (0x20, 0x09):
                continue
            nr ^= (((nr & 63) + add) * c) + (nr << 8)
            nr2 += (nr2 << 8) ^ nr
            nr &= 0x7FFFFFFF
            nr2 &= 0x7FFFFFFF
        nr &= 0x7FFFFFFF
        nr2 &= 0x7FFFFFFF
        return f"{nr:x}{nr2:x}" == target

    @staticmethod
    def _v_mysql_sha1(pw, target, extra):
        return hashlib.sha1(hashlib.sha1(pw.encode()).digest()).hexdigest() == target

    @staticmethod
    def _v_mssql(pw, target, extra):
        h = hashlib.sha1(pw.encode() + b'0123456789ABCDEF').hexdigest().upper()
        return h == target.upper()

    @staticmethod
    def _v_mssql05(pw, target, extra):
        u = pw.upper().encode()
        h = hashlib.sha1(hashlib.sha1(u).digest()).hexdigest().upper()
        return h == target.upper()

    @staticmethod
    def _v_mssql12(pw, target, extra):
        u = pw.upper().encode()
        h = hashlib.sha1(u + b'\x0a' + u).hexdigest().upper()
        return h == target.upper()

    @staticmethod
    def _v_postgres(pw, target, extra):
        user = extra.get('username', '')
        h = hashlib.md5(pw.encode() + user.encode()).hexdigest()
        return h == target or ('md5' + h) == target

    @staticmethod
    def _v_oracle_o10g(pw, target, extra):
        h1 = hashlib.md5(pw.encode()).hexdigest()
        h2 = hashlib.md5((h1 + pw).encode()).hexdigest()
        h3 = hashlib.md5(h2.encode()).hexdigest()
        return h3 == target

    @staticmethod
    def _v_django(pw, target, extra):
        parts = target.split('$')
        if len(parts) < 3:
            return False
        algo = parts[0]
        salt = parts[1]
        h_target = parts[2]
        if algo == 'pbkdf2_sha256':
            dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 10000)
            h = base64.b64encode(dk).decode().strip('=')
            return h == h_target
        elif algo == 'md5':
            return hashlib.md5(salt.encode() + pw.encode()).hexdigest() == h_target
        return False

    @staticmethod
    def _v_phps2(pw, target, extra):
        parts = target.split('$')
        if len(parts) < 4:
            return False
        salt = parts[2]
        h_target = parts[3]
        h = hashlib.md5((hashlib.md5(pw.encode()).hexdigest() + salt).encode()).hexdigest()
        return h == h_target

    @staticmethod
    def _v_tacacs(pw, target, extra):
        try:
            chal = bytes.fromhex(extra.get('salt', ''))
            return hashlib.md5(pw.encode() + chal).hexdigest() == target
        except Exception:
            return False

    @staticmethod
    def _v_plaintext(pw, target, extra):
        return pw == target

    @staticmethod
    def _v_asa_md5(pw, target, extra):
        return hashlib.md5(pw.encode() + extra.get('salt', '').encode()).hexdigest() == target

    @staticmethod
    def _v_sybase_ase(pw, target, extra):
        return hashlib.sha1(pw.encode()).hexdigest().upper() == target.upper()

    def get_result(self):
        return {
            'success': self.found_password is not None,
            'hash_type': self.hash_type,
            'password': self.found_password,
            'target_hash': self.target,
            'payload_used': self.selected_payload,
        }
