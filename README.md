# dsleak

[![CI](https://github.com/JonasChen0103/dsleak/actions/workflows/ci.yml/badge.svg)](https://github.com/JonasChen0103/dsleak/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A **`.DS_Store` file disclosure exploit**. It downloads a leaked `.DS_Store`, parses the file names it records, and recursively downloads every listed file and sub-directory `.DS_Store`.

[繁體中文說明](#繁體中文說明)

> **Legal notice:** use this tool only against systems you own or are explicitly authorized to test. Unauthorized access to computer systems is illegal.

## Background

macOS Finder writes a hidden `.DS_Store` file into every folder it opens. The file stores view settings **and the names of the files in that folder**. When a developer uploads a whole project directory to a web server, the `.DS_Store` files go with it, and anyone can fetch them to list the directory's contents, including backups, config files and admin pages that are not linked anywhere.

## Features

- Recursive crawl: every listed name is downloaded, and every name that looks like a directory is probed for its own `.DS_Store`.
- Concurrent requests with a configurable thread pool.
- Mirrors the remote layout under `<output>/<host>/...`.
- Safe by default: rejects path traversal entries such as `../../etc/passwd`, sanitizes file names that are illegal on Windows, and never writes outside the output directory.
- Detects soft-404 pages (servers that answer `200` with an HTML error page) by checking the `.DS_Store` magic bytes.
- Request timeout, custom User-Agent, optional TLS verification bypass, proxy support through `HTTP_PROXY` / `HTTPS_PROXY`.
- One small dependency ([`ds_store`](https://pypi.org/project/ds-store/)); HTTP is done with the standard library.

## Pitfalls handled

| Naive approach | dsleak |
| --- | --- |
| `url.rstrip('.DS_Store')` strips *characters*, not the suffix, so `/store/.DS_Store` turns into `/` and the crawl goes to the wrong place | Suffix is removed exactly |
| No request timeout, so one slow server hangs the scan forever | `--timeout` (default 10 s) |
| Thread counter decremented without a lock; termination relied on a 2-second queue timeout | Breadth-first crawl on `ThreadPoolExecutor`, no shared counters, exits as soon as work is done |
| Any `200` response saved as a `.DS_Store` and handed to the parser | Magic bytes checked before parsing; soft-404 pages are reported and skipped |
| Path traversal check compared against the current directory, not the actual write location | Every entry must be a single path component, and the final path is verified to be inside the output directory |
| Characters such as `:` `?` `*` in names crash the download on Windows | Illegal characters are replaced with `_` |
| File names with spaces or non-ASCII characters were not URL-encoded | Names are percent-encoded |
| Hard-coded 10 threads, current directory only, no TLS or User-Agent options | `-t`, `-o`, `-k`, `-A`, `-v` options |

## Installation

```bash
pip install git+https://github.com/JonasChen0103/dsleak.git
```

Or run the script directly:

```bash
git clone https://github.com/JonasChen0103/dsleak.git
cd dsleak
pip install ds-store
python dsleak.py https://www.example.com/.DS_Store
```

## Usage

```
dsleak [-h] [-o OUTPUT] [-t THREADS] [--timeout TIMEOUT] [-k]
       [-A USER_AGENT] [-v] [-V]
       url
```

| Option | Description | Default |
| --- | --- | --- |
| `url` | Target `.DS_Store` URL, or the directory that contains it. The scheme and the `/.DS_Store` suffix are added when missing. | required |
| `-o, --output` | Output directory | `.` |
| `-t, --threads` | Concurrent requests | `10` |
| `--timeout` | Request timeout in seconds | `10` |
| `-k, --insecure` | Skip TLS certificate verification | off |
| `-A, --user-agent` | User-Agent header | a desktop Chrome UA |
| `-v, --verbose` | Also report non-200 responses | off |
| `-V, --version` | Print the version | |

The exit code is `0` when at least one file was saved, `1` when nothing was found, and `130` when interrupted.

### Examples

```bash
# All three forms are equivalent
dsleak https://www.example.com/.DS_Store
dsleak https://www.example.com/
dsleak www.example.com

# Save into ./loot with 20 threads through Burp
HTTPS_PROXY=http://127.0.0.1:8080 dsleak -k -t 20 -o loot https://www.example.com/static/
```

### Sample output

```
$ dsleak -o loot https://www.example.com/
[200] https://www.example.com/.DS_Store
[200] https://www.example.com/admin/.DS_Store
[200] https://www.example.com/backup.zip
[200] https://www.example.com/index.php
[200] https://www.example.com/admin/config.php
[*] Done. 5 file(s) saved under /home/user/loot

$ tree loot
loot
└── www.example.com
    ├── admin
    │   └── config.php
    ├── backup.zip
    └── index.php
```

(`.DS_Store` files are saved too; `tree` hides dotfiles.)

## How it works

1. Fetch `<dir>/.DS_Store` without following redirects. Check that it starts with the `\x00\x00\x00\x01Bud1` magic.
2. Parse the B-tree with the `ds_store` library and collect every recorded file name.
3. Drop unsafe names (`.`, `..`, anything containing `/`, `\` or NUL).
4. Queue `<dir>/<name>` for download. If the name has no file extension, also queue `<dir>/<name>/.DS_Store`.
5. Repeat level by level until no new URLs are found.

Directories whose names contain a short extension (for example `v1.2`) are treated as files and not probed. Pass that directory's URL explicitly to scan it.

## Mitigation

If you run a web server, block access to `.DS_Store` files and remove them from deployments.

**nginx**

```nginx
location ~ /\.DS_Store$ {
    deny all;
}
```

**Apache**

```apache
<Files ".DS_Store">
    Require all denied
</Files>
```

**Clean up and prevent**

```bash
find . -name .DS_Store -delete
echo .DS_Store >> ~/.gitignore_global && git config --global core.excludesfile ~/.gitignore_global
defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool true  # no .DS_Store on network shares
```

## Development

```bash
pip install ds-store
python -m unittest -v
```

The end-to-end test serves a fake leaky site from a temporary directory and checks the recursive download, the path traversal guard and the soft-404 check.

## 繁體中文說明

這是一個 **`.DS_Store` 檔案洩漏利用工具**。它會下載網站上外洩的 `.DS_Store`，解析其中記錄的檔名，再遞迴下載所有列出的檔案與子目錄中的 `.DS_Store`。

主要特色：

- 精確移除 `.DS_Store` 後綴，避免 `rstrip('.DS_Store')` 誤刪字元導致 `/store/.DS_Store` 這類路徑爬錯位置的問題
- 加入請求逾時，避免單一慢速伺服器讓掃描永遠卡住
- 以 `ThreadPoolExecutor` 逐層爬取，不使用共享計數器
- 解析前檢查 magic bytes，可辨識回傳 200 的假 404 頁面
- 更嚴格的路徑穿越防護，確保檔案只會寫入輸出目錄
- 自動替換 Windows 不允許的檔名字元，並對檔名做 URL 編碼
- 支援輸出目錄、執行緒數、逾時、TLS 略過驗證、User-Agent 等選項
- 只需 Python 3.9+ 與 `ds_store` 套件，附自動化測試與 MIT 授權

**安裝與使用**

```bash
pip install git+https://github.com/JonasChen0103/dsleak.git
dsleak -o loot https://www.example.com/.DS_Store
```

**防護建議：** 在 nginx 或 Apache 設定中拒絕存取 `.DS_Store`，部署前用 `find . -name .DS_Store -delete` 清除，並將 `.DS_Store` 加入全域 `.gitignore`。

> **法律聲明：** 本工具僅限用於您擁有或已取得明確授權測試的系統，未經授權存取他人系統屬違法行為。

## Credits

`.DS_Store` parsing: [ds_store](https://github.com/dmgbuild/ds_store) by Alastair Houghton.

## License

[MIT](LICENSE)
