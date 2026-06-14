import re

class HashIdentifier:
    def run(self):
        print("\n=== Hash Identifier ===")
        h = input("Enter hash: ").strip()
        if not h:
            print("No input.")
            return
        results = self._identify(h)
        if results:
            print("\nPossible hash matches:")
            for name, pct in results:
                bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
                print(f"  {bar}  {pct:3d}%  {name}")
        else:
            print("\nNo known hash type matches this input.")

    @staticmethod
    def _identify(h):
        matches = []
        add = lambda n, p: matches.append((n, p))

        parts = h.split('$')
        h_len = len(h)
        h_lower = h.lower()

        is_hex = all(c in '0123456789abcdef' for c in h_lower)
        is_hex_upper = h == h.upper() and all(c in '0123456789ABCDEF' for c in h)
        is_base64 = all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in h)

        if h.startswith('$argon2i$') or h.startswith('$argon2d$') or h.startswith('$argon2id$'):
            add("Argon2", 99)

        if h.startswith('$7$') and len(parts) >= 4:
            add("scrypt ($7$)", 98)

        if h.startswith('$1$') and len(parts) >= 4:
            add("md5crypt ($1$)", 98)

        if h.startswith('$2a$') or h.startswith('$2b$') or h.startswith('$2y$'):
            add("bcrypt ($2a$/$2b$/$2y$)", 99)

        if h.startswith('$5$') and len(parts) >= 4:
            if 'rounds=' in parts[1]:
                add("sha256crypt ($5$ with rounds)", 98)
            else:
                add("sha256crypt ($5$)", 98)

        if h.startswith('$6$') and len(parts) >= 4:
            if 'rounds=' in parts[1]:
                add("sha512crypt ($6$ with rounds)", 98)
            else:
                add("sha512crypt ($6$)", 98)

        if h.startswith('$md5$'):
            add("SunMD5 ($md5$)", 97)

        if h.startswith('$P$') or h.startswith('$H$'):
            add("phpass (WordPress / phpBB / Drupal)", 98)

        if h.startswith('$2$'):
            add("bcrypt ($2$) (deprecated)", 95)

        if h.startswith('$krb5pa$'):
            add("Kerberos 5 pre-auth (KRB5PA-MD5)", 98)

        if h.startswith('$DCC2$'):
            add("Domain Cached Credentials 2 (DCC2)", 98)

        if h.startswith('$challenge$'):
            add("MSCHAPv2 challenge/response", 95)

        if h.startswith('pbkdf2_sha256$'):
            add("Django PBKDF2-SHA256", 99)

        if h.startswith('pbkdf2_sha1$'):
            add("Django PBKDF2-SHA1", 99)

        if '$' in h and len(parts) == 3 and parts[0] in ('md5', 'sha1', 'sha256', 'sha384', 'sha512'):
            add(f"Django {parts[0].upper()}", 95)

        if h.startswith('{SHA}'):
            add("LDAP SHA-1", 98)

        if h.startswith('{SSHA}'):
            add("LDAP SSHA", 98)

        if h.startswith('{SSHA256}'):
            add("LDAP SSHA-256", 98)

        if h.startswith('{SSHA512}'):
            add("LDAP SSHA-512", 98)

        if h.startswith('{MD5}'):
            add("LDAP MD5", 98)

        if h.startswith('{SMD5}'):
            add("LDAP SMD5", 98)

        if h.startswith('{CRYPT}'):
            add("LDAP CRYPT", 95)

        if h.startswith('{PBKDF2}'):
            add("LDAP PBKDF2", 95)

        if is_hex and h_len == 32:
            add("MD5", 75)
            add("NTLM", 55)
            add("PostgreSQL MD5", 45)
            add("MySQL 4.1+ (double SHA-1)", 40)
            if is_hex_upper:
                add("LM (LAN Manager)", 50)
            add("MD4", 25)
            add("MD5u (MD5 Unicode)", 20)
            add("RIPEMD-128", 15)
            add("Haval-128", 10)
            add("Tiger-128", 10)

        if is_hex and h_len == 16:
            add("MySQL OLD_PASSWORD (pre-4.1)", 85)
            add("Oracle 10g/11g hash (16 hex)", 65)
            add("CRC64", 40)

        if is_hex and h_len == 8:
            add("CRC32 / Adler32", 60)
            add("Cisco IOS type 7", 55)

        if is_hex and h_len == 40:
            add("SHA-1", 85)
            add("MySQL 5 (SHA-1(SHA-1()))", 45)
            add("SHA-0", 20)
            add("RIPEMD-160", 20)
            add("Haval-160", 10)
            add("Tiger-160", 10)

        if is_hex and h_len == 56:
            add("SHA-224", 75)
            add("SHA3-224", 60)
            add("Blake2s-224", 45)
            add("Haval-224", 15)

        if is_hex and h_len == 64:
            add("SHA-256", 85)
            add("SHA3-256", 55)
            add("Blake2b-256", 45)
            add("Blake2s-256", 40)
            add("GOST R 34.11-2012 (Stribog-256)", 25)
            add("Skein-256", 20)
            add("Haval-256", 10)

        if is_hex and h_len == 96:
            add("SHA-384", 80)
            add("SHA3-384", 60)
            add("Blake2b-384", 45)
            add("Skein-384", 20)

        if is_hex and h_len == 128:
            add("SHA-512", 80)
            add("SHA3-512", 60)
            add("Blake2b-512", 50)
            add("GOST R 34.11-2012 (Stribog-512)", 25)
            add("Skein-512", 20)

        if is_hex and h_len == 14:
            add("CRC16", 50)

        if is_hex and h_len == 24:
            add("DES crypt (2-char salt + 11-char hash)", 70)

        if is_hex and h_len == 48:
            add("SHA-384 half / Skein-384 half", 30)

        if is_hex and h_len == 28:
            add("NTLM half (14 bytes)", 65)

        if ':' in h:
            parts_colon = h.split(':')
            if len(parts_colon) == 2:
                ph = parts_colon[0].lower()
                if re.match(r'^[0-9a-f]{32}$', ph):
                    add(f"NTLM with salt (salt: {parts_colon[1]})", 60)
                    add(f"MD5 with salt (salt: {parts_colon[1]})", 55)
                elif re.match(r'^[0-9a-f]{40}$', ph):
                    add(f"SHA-1 with salt (salt: {parts_colon[1]})", 70)
                elif re.match(r'^[0-9a-f]{64}$', ph):
                    add(f"SHA-256 with salt (salt: {parts_colon[1]})", 60)
                elif re.match(r'^[0-9a-f]{16}$', ph):
                    add(f"MySQL OLD_PASSWORD or CRC64 with salt (salt: {parts_colon[1]})", 50)

        if h_lower.startswith('md5') and len(h) == 35:
            add("PostgreSQL MD5 (md5<hex>)", 95)

        if h_lower.startswith('0x') and is_hex:
            add("Oracle / MySQL hex hash", 60)

        if h.isdigit():
            add("Cisco IOS type 7", 55)
            add("Oracle numeric hash", 45)
            add("CRC32 (decimal)", 35)

        if is_base64 and h_len == 20 and not h.startswith('{'):
            add("LM:NS response / Base64 hash", 55)

        if is_hex and h_len == 12:
            add("CRC32 / possible short hash", 45)

        if not matches:
            add("Unknown hash format", 0)

        seen = set()
        unique = []
        for name, pct in matches:
            if name not in seen:
                seen.add(name)
                unique.append((name, pct))
        unique.sort(key=lambda x: -x[1])

        return unique

    def get_result(self):
        return {}
