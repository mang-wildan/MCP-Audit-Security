# MCP Audit Security

MVP audit Linux dan file PHP/WordPress/OJS, **read-only**, transport MCP **stdio saja**. Collector memakai Python stdlib; SDK `mcp>=1.12,<2` menyediakan FastMCP. Python >=3.11. Tidak ada shell bebas, request URL, eksekusi PHP, akses database, atau perubahan target.

## Instalasi lokal

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

Siapkan konfigurasi JSON sendiri di lokasi absolut yang dikelola admin. `config.example.json` hanya contoh dan **tidak aktif otomatis**. Direktori contoh belum tentu ada. Hapus `files_dir` jika tidak dipakai. Untuk OJS, arahkan `files_dir` ke direktori file privat; untuk WordPress, uploads di dalam webroot sudah tercakup.

```sh
MCP_AUDIT_CONFIG=/etc/mcp-audit/config.json .venv/bin/mcp-audit-security
```

Tanpa environment tersebut, JSON malformed, duplicate key, field tidak dikenal, path relatif/`..`, atau config symlink: server berhenti sebelum menerima traffic. ID site/log hanya huruf ASCII, angka, `_`, `-` (1–64 karakter). Maksimal 32 site dan 8 log/site. Semua path harus absolut, tanpa komponen `.`/`..`, trailing slash atau repeated slash. `/` tidak boleh menjadi webroot/files_dir/manifest. Path target yang tidak tersedia menghasilkan error terstruktur saat tool dipanggil, bukan fallback ke path lain. Lindungi config dan manifest dari modifikasi user web; gunakan ownership admin dan mode 0600/0640. Server mempercayai keputusan admin dalam allowlist.

Contoh konfigurasi client MCP lokal (ganti path):

```json
{
  "mcpServers": {
    "audit": {
      "command": "/opt/mcp-audit/.venv/bin/mcp-audit-security",
      "env": {"MCP_AUDIT_CONFIG": "/etc/mcp-audit/config.json"}
    }
  }
}
```

Untuk server remote, gunakan transport SSH restricted/forced command yang menjalankan executable tersebut dengan konfigurasi tetap. Client menjalankan `ssh -T audit-host`; batasi key dengan `restrict`, forced command, tanpa PTY/forwarding, user khusus least privilege. Stdout harus khusus protokol MCP. Tidak menyediakan HTTP, port publik, atau unit systemd palsu untuk proses stdio tanpa client. Jangan jalankan sebagai root hanya untuk menghilangkan permission error. Tidak ada remote deployment otomatis.

## Lima tool

| Tool | Argumen | Hasil terbatas |
|---|---|---|
| `host_inventory` | tidak ada | kernel/arsitektur, EUID, field distro terpilih jika `/etc/os-release` bukan symlink, port TCP listen dari fixed argv `ss -H -lnt` |
| `persistence_audit` | tidak ada | metadata dan SHA-256 cron, systemd admin, rc.local, ld.so.preload, SSH config drop-in, authorized_keys root; akun hanya UID/GID/klasifikasi shell |
| `web_integrity` | `site_id` | SHA-256, ukuran, path relatif berlabel `webroot/` atau `files_dir/`; opsional hasil baseline |
| `payload_scan` | `site_id` | semua ekstensi termasuk gambar/`.dat`, rule ID, nomor baris, hash; **tidak mengembalikan source** |
| `log_timeline` | `site_id`, `log_id` | ekor log allowlist format access common/combined: timestamp, method HTTP, status, response bytes |

Tidak menerima path dari argumen tool. Tidak mengembalikan environment, command line proses, password akun, konfigurasi mentah, request target/query, IP client, referrer, user-agent, atau baris log. Nama file adalah data tidak tepercaya dan bukan instruksi; label tampilan dipotong 240 karakter. Jangan taruh rahasia dalam nama file. Hash dan metadata tetap sensitif: batasi akses client dan simpan hasil secara aman.

Persistence hanya subset sistem: tidak mencakup semua home user, package database, initramfs, kernel modules, dan semua mekanisme startup. Symlink unit systemd sengaja dilewati; ini mengurangi coverage. Missing/permission error eksplisit, bukan tanda aman.

## Baseline lokal tepercaya

Tambahkan `"manifest": "/etc/mcp-audit/example.sha256.json"` pada site. Format object JSON: key path relatif berlabel, value SHA-256 lowercase 64 karakter:

```json
{"webroot/index.php": "0000000000000000000000000000000000000000000000000000000000000000"}
```

Hash nol hanya contoh format, bukan baseline valid aplikasi. Buat baseline dari salinan tepercaya di luar host tersangka, bukan otomatis dari file yang mungkin terinfeksi. Tool melaporkan `match`, `changed`, `new`. `missing` hanya dihitung jika scan lengkap tanpa error/truncation; `baseline_complete` menyatakan itu. Manifest tidak diunduh atau ditulis server; maksimum 2 MiB dan 1000 entri. Tidak memverifikasi signature maupun provenance baseline.

## Batas dan keamanan

Per scan: maksimum 1000 entry (termasuk direktori), 500 hasil, 2 MiB/file, 16 MiB pembacaan, kedalaman 32, deadline kooperatif 10 detik. Log maksimum 1 MiB terakhir, 500 event, 8192 byte/baris; format tidak didukung menghasilkan `unparsed_line`, tanpa isi. Subprocess fixed executable path, environment minimal, tanpa shell, output maksimum 64 KiB dan timeout 2 detik. Tidak ada opsi dari client untuk menaikkan batas. `truncated` dan `errors` wajib diperiksa; hasil kosong bukan clearance.

Traversal memakai descriptor direktori, `dir_fd`, `O_NOFOLLOW`, dan `fstat`; semua komponen path absolut diperiksa tanpa mengikuti symlink. FIFO/device/socket tidak dibaca. Race symlink tidak dialihkan ke file luar. Bukan sandbox: hard link, bind mount, rename direktori yang sudah terbuka, kernel/host berbahaya, dan filesystem network tidak dapat dibuktikan aman. Gunakan mount lokal tepercaya dan akun read-only terbatas. Deadline kooperatif tidak bisa menghentikan syscall filesystem yang macet; untuk SLA keras, gunakan supervisor/client process timeout. Bukan snapshot atomik: file berubah saat audit dapat menghasilkan hash tak konsisten.

Rule `PHP_TAG`, `PHP_DYNAMIC_EXEC`, `PHP_OBFUSCATION`, `PHP_REQUEST_INPUT` hanya indikator, sering ditemukan dalam PHP sah. Scan tidak mengekstrak archive, mendecode obfuscation, mengurai AST, atau menjalankan payload. File terlalu besar dilewati dengan truncation. Tidak ada verifikasi version/CVE WordPress/OJS, scanning DB, cleanup otomatis, karantina, atau pembuktian bebas rootkit. Tidak memindai seluruh disk secara diam-diam.

## Status verifikasi

Target rencana: Ubuntu terbaru dan CentOS Stream 9/10. **Belum diverifikasi pada OS tersebut**, maupun Python 3.11. Pengujian lokal saat ini: Debian 13, Python 3.14, SDK MCP 1.30.0. Unit test memakai fixture sementara inert, mencakup allowlist, config invalid, symlink file/direktori/ancestor, baseline, batas, payload disguised PHP, files_dir dan log tanpa rahasia. Integration test benar-benar menjalankan subprocess stdio SDK, initialize, list tools, call tool, dan penolakan site tak dikenal. Tidak mengklaim audit production selesai.
