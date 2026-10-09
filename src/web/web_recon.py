import re
import time
import urllib.request
import urllib.parse
import urllib.error
from html.parser import HTMLParser
from utils.menu import Menu

USER_AGENT = "PwnStar-Toolkit/1.0 (+CTF recon)"
TIMEOUT = 8

# Small built-in path list for quick CTF discovery. Point the scanner at a
# custom wordlist file for anything larger.
COMMON_PATHS = [
    "robots.txt", "sitemap.xml", ".git/HEAD", ".git/config", ".env",
    "admin", "admin/", "administrator", "login", "login.php", "dashboard",
    "backup", "backup.zip", "backup.tar.gz", "flag", "flag.txt", "flags.txt",
    "secret", "secret.txt", "config", "config.php", "config.json",
    "wp-admin", "wp-login.php", "phpinfo.php", "info.php", "test.php",
    "uploads", "uploads/", "images/", "assets/", "api", "api/", "api/v1",
    "server-status", ".htaccess", ".htpasswd", "index.php.bak", "index.bak",
    "db.sql", "database.sql", "dump.sql", "users.txt", "hidden", "dev",
    "old", "tmp", "private", ".svn/entries", "readme.txt", "CHANGELOG",
]


class _LinkCommentParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = set()
        self.forms = []
        self.comments = []
        self._cur_form = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a" and d.get("href"):
            self.links.add(d["href"])
        elif tag in ("script", "link") and (d.get("src") or d.get("href")):
            self.links.add(d.get("src") or d.get("href"))
        elif tag == "form":
            self._cur_form = {
                "action": d.get("action", ""),
                "method": d.get("method", "GET").upper(),
                "inputs": [],
            }
        elif tag == "input" and self._cur_form is not None:
            self._cur_form["inputs"].append(d.get("name", "(unnamed)"))

    def handle_endtag(self, tag):
        if tag == "form" and self._cur_form is not None:
            self.forms.append(self._cur_form)
            self._cur_form = None

    def handle_comment(self, data):
        self.comments.append(data.strip())


class WebRecon:
    def run(self):
        print("\n=== Web Recon ===")
        items = [
            "HTTP Headers",
            "Directory / File Scan",
            "robots.txt / sitemap.xml",
            "HTML Comments / Links / Forms",
        ]
        menu = Menu(items, back=True)
        choice = menu.run()
        print()

        if choice is None:
            return
        elif choice == 0:
            self._headers()
        elif choice == 1:
            self._dir_scan()
        elif choice == 2:
            self._robots()
        elif choice == 3:
            self._extract()

    # ---- helpers -------------------------------------------------------
    @staticmethod
    def _normalize(url):
        url = url.strip()
        if not url:
            return ""
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url

    @staticmethod
    def _fetch(url, method="GET"):
        req = urllib.request.Request(
            url, method=method, headers={"User-Agent": USER_AGENT}
        )
        return urllib.request.urlopen(req, timeout=TIMEOUT)

    # ---- tools ---------------------------------------------------------
    def _headers(self):
        url = self._normalize(input("Target URL: "))
        if not url:
            print("No URL.")
            return
        try:
            resp = self._fetch(url, method="HEAD")
        except urllib.error.HTTPError as e:
            resp = e  # HTTPError still carries status + headers
        except Exception as e:
            print(f"Request failed: {e}")
            return

        print(f"\nStatus: {resp.status} {resp.reason}")
        print("Headers:")
        flagged = ("server", "x-powered-by", "set-cookie", "location",
                   "x-flag", "www-authenticate")
        for k, v in resp.getheaders():
            mark = "  \033[93m<--\033[0m" if k.lower() in flagged else ""
            print(f"  {k}: {v}{mark}")

    def _dir_scan(self):
        base = self._normalize(input("Base URL: "))
        if not base:
            print("No URL.")
            return
        if not base.endswith("/"):
            base += "/"

        wl = input("Wordlist file (blank = built-in list): ").strip()
        if wl:
            try:
                with open(wl, "r", errors="ignore") as f:
                    paths = [ln.strip() for ln in f if ln.strip()
                             and not ln.startswith("#")]
            except OSError as e:
                print(f"Could not read wordlist: {e}")
                return
        else:
            paths = COMMON_PATHS

        delay_s = input("Delay between requests in seconds (default 0): ").strip()
        try:
            delay = float(delay_s) if delay_s else 0.0
        except ValueError:
            delay = 0.0

        print(f"\nScanning {len(paths)} paths against {base}\n")
        found = []
        for path in paths:
            url = urllib.parse.urljoin(base, path)
            try:
                resp = self._fetch(url)
                code = resp.status
                length = resp.headers.get("Content-Length", "?")
            except urllib.error.HTTPError as e:
                code = e.code
                length = e.headers.get("Content-Length", "?") if e.headers else "?"
            except Exception:
                continue

            if code < 400 or code in (401, 403):
                color = "92" if code < 300 else ("93" if code < 400 else "91")
                print(f"  \033[{color}m[{code}]\033[0m {url}  (len {length})")
                found.append((code, url))
            if delay:
                time.sleep(delay)

        print(f"\nDone. {len(found)} interesting path(s) found.")

    def _robots(self):
        base = self._normalize(input("Base URL: "))
        if not base:
            print("No URL.")
            return
        for name in ("robots.txt", "sitemap.xml"):
            url = urllib.parse.urljoin(base + "/", name)
            print(f"\n--- {url} ---")
            try:
                resp = self._fetch(url)
                body = resp.read(20000).decode(errors="replace")
                print(body if body.strip() else "(empty)")
            except urllib.error.HTTPError as e:
                print(f"HTTP {e.code}")
            except Exception as e:
                print(f"Request failed: {e}")

    def _extract(self):
        url = self._normalize(input("Target URL: "))
        if not url:
            print("No URL.")
            return
        try:
            resp = self._fetch(url)
            html = resp.read(500000).decode(errors="replace")
        except urllib.error.HTTPError as e:
            try:
                html = e.read(500000).decode(errors="replace")
            except Exception:
                print(f"HTTP {e.code}")
                return
        except Exception as e:
            print(f"Request failed: {e}")
            return

        parser = _LinkCommentParser()
        try:
            parser.feed(html)
        except Exception:
            pass

        print(f"\n\033[1mHTML Comments ({len(parser.comments)}):\033[0m")
        for c in parser.comments:
            if c:
                print(f"  <!-- {c} -->")
        if not any(parser.comments):
            print("  (none)")

        print(f"\n\033[1mLinks / Resources ({len(parser.links)}):\033[0m")
        for link in sorted(parser.links):
            print(f"  {link}")

        print(f"\n\033[1mForms ({len(parser.forms)}):\033[0m")
        for form in parser.forms:
            print(f"  {form['method']} {form['action'] or '(self)'}"
                  f"  inputs: {', '.join(form['inputs']) or '(none)'}")

        # flag-looking strings are a common CTF giveaway; drop style/script
        # blocks first so CSS rules like `body{...}` don't match.
        stripped = re.sub(r"<(style|script)\b[^>]*>.*?</\1>", "", html,
                          flags=re.I | re.S)
        hits = [h for h in re.findall(r"[A-Za-z0-9_]{2,}\{[^{}]{1,100}\}", stripped)
                if ";" not in h]
        if hits:
            print(f"\n\033[93mPossible flags:\033[0m")
            for h in set(hits):
                print(f"  {h}")

    def get_result(self):
        return {'tool': 'Web Recon'}
