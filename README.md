# ULP Sorter (Tkinter)

Fast desktop log sorter for large ULP-style log datasets.

## What it does

- Scans a selected logs directory recursively
- Matches lines by:
  - **Subdomains**
  - **Paths**
  - **Ports**
  - **Usernames**
- Skips saving entries when:
  - password is exactly **`[NOT_SAVED]`**
  - host is a **local/private IP** (e.g. `10.x.x.x`, `192.168.x.x`, `127.x.x.x`, `172.16-31.x.x`)
- Safety: skips extremely long lines (default 1 MiB) to avoid OOM on binary/no-newline files
- Uses your requested base keyword set by default
- Lets you add custom keywords per category
- Writes matches to **separate files per keyword** in real time
- Shows live progress for files, bytes, lines, speed, and match counts
- Designed for very large files (multi-GB) and many files (hundreds+)

## Base keywords (default)

- Subdomains:
  - `guacamole.*`
  - `mail.*`
  - `webmail.*`
  - `cpanel.*`
  - `metabase.*`
  - `gitlab.*`
  - `rdweb.*`
  - `smtp.*`
- Paths:
  - `/owa/auth/logon.aspx`
  - `/rdweb/`
  - `/guacamole/`
  - `/adminer2.php`
  - `/adminer.php`
- Ports:
  - `:2083`
  - `22`
  - `21`
  - `587`
  - `25`
  - `465`
- Username:
  - `admin`

## Run

```bash
python3 ulp_sorter.py
```

### If Tkinter is missing (Linux)

Some minimal Python installs do not include Tkinter. On Ubuntu/Debian:

```bash
sudo apt-get update && sudo apt-get install -y python3-tk
```

## How to use

1. Click **Browse** and select your logs directory.
2. Add any custom keywords (optional):
   - Subdomains
   - Paths
   - Ports
   - Usernames
3. Choose worker count (defaults to CPU-based value).
4. Click **Start Scan**.
5. Watch live progress and per-keyword counters.

## Output

- Output folder is created inside the selected logs directory:
  - `ulp_sorted_output_YYYYMMDD_HHMMSS/`
- Inside it, data is split by category and keyword:
  - `subdomains/*.txt`
  - `paths/*.txt`
  - `ports/*.txt`
  - `usernames/*.txt`
- `summary.txt` is written at the end with totals and per-keyword counts.

## Performance notes

- Binary streaming reads (no full-file loading)
- Multi-threaded file processing
- Buffered per-keyword chunk writes
- Real-time counters without blocking the UI

## Code layout

- `ulp_sorter.py` - Tkinter GUI (directory picker + live progress)
- `ulp_sorter_engine.py` - fast scanner engine (no GUI dependency)

## Testing

```bash
python3 -m unittest discover -s tests -p "test*.py"
```
