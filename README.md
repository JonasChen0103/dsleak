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
- Safe by default: skips path traversal entries such as `../../etc/passwd`, sanitizes file names that are illegal on Windows, and never writes outside the output directory.
- `--allow-traversal` requests those entries anyway, for pentests and CTFs where they are the point; the responses are still saved inside the output directory (`..` becomes `__`).
- Pass a local `.DS_Store` file instead of a URL to just list the names it records.
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

Install it as a `dsleak` command with [uv](https://docs.astral.sh/uv/) (recommended) or pipx. Both keep it in an isolated environment, so it also works on Pythons that block global `pip install` (PEP 668):

```bash
uv tool install git+https://github.com/JonasChen0103/dsleak.git
# or
pipx install git+https://github.com/JonasChen0103/dsleak.git
# or, inside a virtual environment
pip install git+https://github.com/JonasChen0103/dsleak.git
```

Upgrade with `uv tool upgrade dsleak`, remove with `uv tool uninstall dsleak`.

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
       [-A USER_AGENT] [--allow-traversal] [-v] [-V]
       url
```

| Option | Description | Default |
| --- | --- | --- |
| `url` | Target `.DS_Store` URL, or the directory that contains it. The scheme and the `/.DS_Store` suffix are added when missing. A local `.DS_Store` file path lists its names without sending any request. | required |
| `-o, --output` | Output directory | `.` |
| `-t, --threads` | Concurrent requests | `10` |
| `--timeout` | Request timeout in seconds | `10` |
| `-k, --insecure` | Skip TLS certificate verification | off |
| `-A, --user-agent` | User-Agent header | a desktop Chrome UA |
| `--allow-traversal` | Also request entries such as `../x` or `a/b`; files are still saved inside the output directory | off |
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

# Also request traversal entries such as ../../etc/passwd
dsleak --allow-traversal -o loot http://ctf.example.com/

# List the names in a .DS_Store you already downloaded (no requests)
dsleak ~/Downloads/.DS_Store
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
3. Drop unsafe names (`.`, `..`, anything containing `/`, `\` or NUL) unless `--allow-traversal` is set.
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
git clone https://github.com/JonasChen0103/dsleak.git
cd dsleak
uv run python -m unittest -v    # creates .venv and installs dependencies automatically
# without uv: python -m venv .venv, activate it, pip install ds-store, python -m unittest -v
```

To use your working copy as the `dsleak` command, install it in editable mode; code changes take effect without reinstalling:

```bash
uv tool install -e .
```

The end-to-end test serves a fake leaky site from a temporary directory and checks the recursive download, the path traversal guard and the soft-404 check.

## 繁體中文說明

這是一個 **`.DS_Store` 檔案洩漏利用工具**。它會下載網站上外洩的 `.DS_Store`，解析其中記錄的檔名，再遞迴下載所有列出的檔案，以及各子目錄中的 `.DS_Store`。

> **法律聲明：** 本工具僅限用於您擁有或已取得明確授權測試的系統，未經授權存取他人電腦系統屬違法行為。

### 背景

macOS 的 Finder 會在每個開啟過的資料夾裡寫入隱藏的 `.DS_Store` 檔案，用來記錄檢視設定**以及該資料夾內的檔名**。開發者若把整個專案目錄上傳到網頁伺服器，`.DS_Store` 也會跟著上去，任何人都能下載它來列出目錄內容，包括沒有任何連結指向的備份檔、設定檔與管理頁面。

### 功能

- 遞迴爬取：下載所有列出的檔名，並對看起來像目錄的名稱繼續探測其 `.DS_Store`。
- 可設定執行緒數量的並行請求。
- 依照遠端結構存放於 `<output>/<host>/...`。
- 預設安全：略過 `../../etc/passwd` 這類路徑穿越項目、替換 Windows 不允許的檔名字元，且絕不寫入輸出目錄以外的位置。
- 滲透測試或 CTF 需要時，可用 `--allow-traversal` 照樣請求這些項目；回應仍只會存進輸出目錄內（`..` 會改成 `__`）。
- 參數改給本機的 `.DS_Store` 檔案而非 URL，即可直接列出其中記錄的檔名。
- 檢查 `.DS_Store` 的 magic bytes，可辨識軟 404 頁面（回傳 `200` 但內容是 HTML 錯誤頁的伺服器）。
- 支援請求逾時、自訂 User-Agent、略過 TLS 憑證驗證，以及透過 `HTTP_PROXY` / `HTTPS_PROXY` 使用代理伺服器。
- 只有一個小型相依套件（[`ds_store`](https://pypi.org/project/ds-store/)），HTTP 使用標準函式庫處理。

### 已處理的常見問題

| 天真的做法 | dsleak |
| --- | --- |
| `url.rstrip('.DS_Store')` 移除的是*字元*而非後綴，`/store/.DS_Store` 會變成 `/`，導致爬錯位置 | 精確移除後綴 |
| 沒有請求逾時，一台慢速伺服器就能讓掃描永遠卡住 | `--timeout`（預設 10 秒） |
| 執行緒計數器未加鎖就遞減，結束條件依賴 2 秒的佇列逾時 | 以 `ThreadPoolExecutor` 逐層（廣度優先）爬取，沒有共享計數器，工作完成立即結束 |
| 任何 `200` 回應都當成 `.DS_Store` 儲存並交給解析器 | 解析前先檢查 magic bytes，回報並略過軟 404 頁面 |
| 路徑穿越檢查比對的是目前目錄，而非實際寫入位置 | 每個項目都必須是單一路徑元件，並驗證最終路徑位於輸出目錄內 |
| 檔名含 `:` `?` `*` 等字元時，在 Windows 上下載會失敗 | 將不合法字元替換為 `_` |
| 含空白或非 ASCII 字元的檔名沒有做 URL 編碼 | 檔名一律做百分比編碼 |
| 寫死 10 個執行緒、只能存到目前目錄、沒有 TLS 或 User-Agent 選項 | 提供 `-t`、`-o`、`-k`、`-A`、`-v` 選項 |

### 安裝

建議用 [uv](https://docs.astral.sh/uv/) 或 pipx 安裝成 `dsleak` 指令。兩者都會裝在獨立環境中，因此在禁止全域 `pip install` 的 Python（PEP 668）上也能使用：

```bash
uv tool install git+https://github.com/JonasChen0103/dsleak.git
# 或
pipx install git+https://github.com/JonasChen0103/dsleak.git
# 或在虛擬環境中
pip install git+https://github.com/JonasChen0103/dsleak.git
```

更新用 `uv tool upgrade dsleak`，移除用 `uv tool uninstall dsleak`。

或直接執行腳本：

```bash
git clone https://github.com/JonasChen0103/dsleak.git
cd dsleak
pip install ds-store
python dsleak.py https://www.example.com/.DS_Store
```

### 使用方式

```
dsleak [-h] [-o OUTPUT] [-t THREADS] [--timeout TIMEOUT] [-k]
       [-A USER_AGENT] [--allow-traversal] [-v] [-V]
       url
```

| 選項 | 說明 | 預設值 |
| --- | --- | --- |
| `url` | 目標 `.DS_Store` 的 URL，或包含它的目錄。缺少的通訊協定與 `/.DS_Store` 後綴會自動補上。若給的是本機 `.DS_Store` 檔案路徑，則只列出檔名，不發出任何請求。 | 必填 |
| `-o, --output` | 輸出目錄 | `.` |
| `-t, --threads` | 並行請求數 | `10` |
| `--timeout` | 請求逾時（秒） | `10` |
| `-k, --insecure` | 略過 TLS 憑證驗證 | 關閉 |
| `-A, --user-agent` | User-Agent 標頭 | 桌面版 Chrome 的 UA |
| `--allow-traversal` | 一併請求 `../x`、`a/b` 這類項目；檔案仍只會存進輸出目錄內 | 關閉 |
| `-v, --verbose` | 一併顯示非 200 的回應 | 關閉 |
| `-V, --version` | 顯示版本 | |

結束代碼：至少儲存一個檔案時為 `0`，什麼都沒找到時為 `1`，被中斷時為 `130`。

#### 範例

```bash
# 以下三種寫法效果相同
dsleak https://www.example.com/.DS_Store
dsleak https://www.example.com/
dsleak www.example.com

# 透過 Burp、使用 20 個執行緒，存到 ./loot
HTTPS_PROXY=http://127.0.0.1:8080 dsleak -k -t 20 -o loot https://www.example.com/static/

# 一併請求 ../../etc/passwd 這類路徑穿越項目
dsleak --allow-traversal -o loot http://ctf.example.com/

# 列出已下載的 .DS_Store 中記錄的檔名（不發出請求）
dsleak ~/Downloads/.DS_Store
```

#### 輸出範例

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

（`.DS_Store` 也會一併儲存，只是 `tree` 預設不顯示隱藏檔。）

### 運作原理

1. 下載 `<dir>/.DS_Store`（不跟隨重新導向），並確認開頭是 `\x00\x00\x00\x01Bud1` magic bytes。
2. 用 `ds_store` 函式庫解析 B-tree，收集所有記錄的檔名。
3. 捨棄不安全的名稱（`.`、`..`，以及含有 `/`、`\` 或 NUL 的名稱），除非指定了 `--allow-traversal`。
4. 將 `<dir>/<name>` 加入下載佇列；若名稱沒有副檔名，也將 `<dir>/<name>/.DS_Store` 加入佇列。
5. 逐層重複，直到沒有新的 URL 為止。

名稱帶有短副檔名的目錄（例如 `v1.2`）會被視為檔案而不探測。如需掃描，請直接指定該目錄的 URL。

### 防護建議

如果您管理網頁伺服器，請封鎖對 `.DS_Store` 的存取，並在部署時移除這些檔案。

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

**清除與預防**

```bash
find . -name .DS_Store -delete
echo .DS_Store >> ~/.gitignore_global && git config --global core.excludesfile ~/.gitignore_global
defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool true  # 不在網路磁碟上產生 .DS_Store
```

### 開發

```bash
git clone https://github.com/JonasChen0103/dsleak.git
cd dsleak
uv run python -m unittest -v    # 自動建立 .venv 並安裝相依套件
# 不使用 uv：python -m venv .venv，啟用後 pip install ds-store，再執行 python -m unittest -v
```

若想讓 `dsleak` 指令直接使用你的工作副本，請以 editable 模式安裝，修改程式碼後不需重新安裝即可生效：

```bash
uv tool install -e .
```

端對端測試會從暫存目錄架設一個模擬外洩的網站，驗證遞迴下載、路徑穿越防護與軟 404 檢查。

## Credits

`.DS_Store` parsing: [ds_store](https://github.com/dmgbuild/ds_store) by Alastair Houghton.

## License

[MIT](LICENSE)
