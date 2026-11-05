"""End-to-end test: crawl a fake leaky site served from a temp directory."""
import contextlib
import functools
import io
import os
import tempfile
import threading
import unittest
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from ds_store import DSStore

import dsleak as exp


def write_ds_store(path, names):
    with DSStore.open(path, "w+") as d:
        for name in names:
            d[name]["Iloc"] = (0, 0)


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class CrawlTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.site = os.path.join(self.tmp.name, "site")
        self.out = os.path.join(self.tmp.name, "out")
        os.makedirs(os.path.join(self.site, "admin"))
        write_ds_store(os.path.join(self.site, ".DS_Store"),
                       ["index.php", "admin", "../escape", "missing.txt"])
        write_ds_store(os.path.join(self.site, "admin", ".DS_Store"), ["config.json"])
        for rel in ("index.php", "admin/config.json", "escape"):
            with open(os.path.join(self.site, rel), "w") as f:
                f.write("secret " + rel)

        handler = functools.partial(QuietHandler, directory=self.site)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.host = "127.0.0.1:%d" % self.server.server_port

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def test_recursive_download(self):
        saved = exp.Scanner(output=self.out, threads=4).run(self.host)  # no scheme, no suffix
        root = os.path.join(self.out, self.host.replace(":", "_"))
        self.assertEqual(saved, 4)
        for rel in (".DS_Store", "index.php", "admin/.DS_Store", "admin/config.json"):
            self.assertTrue(os.path.isfile(os.path.join(root, rel)), rel)
        with open(os.path.join(root, "admin", "config.json")) as f:
            self.assertEqual(f.read(), "secret admin/config.json")
        self.assertFalse(os.path.exists(os.path.join(self.out, "escape")))

    def test_allow_traversal(self):
        # the test server normalizes /../escape to /escape, like many real ones
        saved = exp.Scanner(output=self.out, allow_traversal=True).run(self.host)
        self.assertEqual(saved, 5)
        root = os.path.join(self.out, self.host.replace(":", "_"))
        self.assertTrue(os.path.isfile(os.path.join(root, "__", "escape")))
        self.assertFalse(os.path.exists(os.path.join(self.out, "escape")))

    def test_list_local_file(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(exp.main([os.path.join(self.site, ".DS_Store")]), 0)
        self.assertEqual(buf.getvalue().split(), sorted(["index.php", "admin", "../escape", "missing.txt"]))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(exp.main([os.path.join(self.site, "index.php")]), 1)

    def test_rejects_soft_404(self):
        with open(os.path.join(self.site, ".DS_Store"), "w") as f:
            f.write("<html>not found</html>")
        self.assertEqual(exp.Scanner(output=self.out).run(self.host), 0)


class HelperTest(unittest.TestCase):
    def test_normalize_url(self):
        n = exp.normalize_url
        self.assertEqual(n("a.com"), "http://a.com/.DS_Store")
        self.assertEqual(n("https://a.com/x/"), "https://a.com/x/.DS_Store")
        self.assertEqual(n("https://a.com/x/.DS_Store"), "https://a.com/x/.DS_Store")
        # a naive rstrip('.DS_Store') would mangle this one
        self.assertEqual(n("https://a.com/store"), "https://a.com/store/.DS_Store")

    def test_unsafe_names(self):
        for name in ("", ".", "..", "../x", "a/b", "a\\b", "x\x00"):
            self.assertFalse(exp.is_safe_name(name), name)
        self.assertTrue(exp.is_safe_name("..hidden"))

    def test_local_path_stays_in_root(self):
        self.assertTrue(exp.local_path("out", "http://a.com/x/%2e%2e/%2e%2e/etc").endswith(
            os.path.join("a.com", "x", "__", "__", "etc")))
        with self.assertRaises(ValueError):
            exp.local_path("out", "http:///")  # no host: would be root itself
        self.assertTrue(exp.local_path("out", "http://a.com:8080/a%2Fb").endswith(
            os.path.join("a.com_8080", "a_b")))


if __name__ == "__main__":
    unittest.main()
