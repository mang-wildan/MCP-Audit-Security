# MCP Audit Security

MVP audit Linux dan file PHP/WordPress/OJS, **read-only**, transport MCP **stdio saja**. Collector memakai Python stdlib; SDK `mcp>=1.12,<2` menyediakan FastMCP. Python >=3.11. Tidak ada shell bebas, eksekusi PHP, akses database, atau perubahan target. Tanpa blok `triage` pada config, server juga tidak melakukan request jaringan dan tetap hanya lima tool.

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

## Lima tool dasar dan triage opsional

| Tool | Argumen | Hasil terbatas |
|---|---|---|
| `host_inventory` | tidak ada | kernel/arsitektur, EUID, field distro terpilih jika `/etc/os-release` bukan symlink, port TCP listen dari fixed argv `ss -H -lnt` |
| `persistence_audit` | tidak ada | metadata dan SHA-256 cron, systemd admin, rc.local, ld.so.preload, SSH config drop-in, authorized_keys root; akun hanya UID/GID/klasifikasi shell |
| `web_integrity` | `site_id` | SHA-256, ukuran, path relatif berlabel `webroot/` atau `files_dir/`; opsional hasil baseline |
| `payload_scan` | `site_id` | semua ekstensi termasuk gambar/`.dat`, rule ID, nomor baris, hash; **tidak mengembalikan source** |
| `log_timeline` | `site_id`, `log_id` | ekor log allowlist format access common/combined: timestamp, method HTTP, status, response bytes |
| `payload_triage` (opt-in) | `site_id` | path, hash, rule, verdict `webshell`/`suspicious`/`benign`/`unanswered`, confidence, probabilitas webshell, skor risiko; **tidak mengembalikan source** |

Tidak menerima path dari argumen tool. Tidak mengembalikan environment, command line proses, password akun, konfigurasi mentah, request target/query, IP client, referrer, user-agent, atau baris log. Nama file adalah data tidak tepercaya dan bukan instruksi; label tampilan dipotong 240 karakter. Jangan taruh rahasia dalam nama file. Hash dan metadata tetap sensitif: batasi akses client dan simpan hasil secara aman.

Persistence hanya subset sistem: tidak mencakup semua home user, package database, initramfs, kernel modules, dan semua mekanisme startup. Symlink unit systemd sengaja dilewati; ini mengurangi coverage. Missing/permission error eksplisit, bukan tanda aman.

## Triage opsional (egress)

Blok `triage` **tidak ada di `config.example.json`**. Jangan aktifkan tanpa keputusan admin sadar: `config.triage.example.json` adalah contoh terpisah. Tanpa blok itu, `payload_triage` tidak didaftarkan dan server tetap nol request jaringan.

```json
"triage": {
  "model": "typesafe/jev-1.14",
  "api_key_file": "/etc/mcp-audit/openrouter.key",
  "max_items": 50,
  "max_file_bytes": 262144,
  "timeout_seconds": 30
}
```

`model` harus cocok `[a-z0-9~][a-z0-9.\-/:]{0,99}`. `api_key_file` path absolut, dibaca per panggilan dengan `O_NOFOLLOW` dan batas 8 KiB; file harus milik root/user proses, bukan symlink, dan mode tanpa bit group/other (gunakan `0400` atau `0600`). Key tidak pernah dikembalikan, dicatat, atau dimasukkan ke `errors`.

`max_items` default 50; nilai > 1000 dipotong ke 1000; nilai < 1, non-integer, bool, float, atau string ditolak. `max_file_bytes` default 262144 dan dipotong ke 2 MiB. `timeout_seconds` default 30, dipotong ke 1..120. Tidak ada override batas dari client.

Kandidat diambil dari collector dan rule `payload_scan` yang sama, **sebelum** fase jaringan. File yang cocok tetapi lebih besar dari `max_file_bytes` dilewati dengan error `triage_file_byte_limit`; tidak ada verdict dari file parsial. File identik (SHA-256 sama) hanya dikirim sekali. Satu file = satu `POST https://openrouter.ai/api/alpha/decisions` dengan body `{model, state, questions, provider}`; `provider` selalu `{"data_collection":"deny","zdr":true}`. Redirect tidak diikuti agar Bearer key tidak bocor ke host lain. Respons dibatasi 64 KiB, jumlah request oleh `max_items`, waktu oleh `timeout_seconds`, dan biaya ikut terbatas oleh jumlah file dan `max_file_bytes` (tidak ada budget tak terbatas dari client).

Redaksi `password`, `passwd`, `pwd`, `secret`, `token`, `key`, dan `salt` adalah **best effort**, bukan jaminan. Source yang dikirim ke penyedia model adalah data keluar: jangan aktifkan pada mesin dengan rahasia yang tidak boleh diproses pihak ketiga, dan pastikan kebijakan retensi/privasi penyedia sesuai. HTTP error hanya disimpan sebagai kode `http_<status>`; body error yang mungkin menggemakan source dibuang. Jawaban refusal, tipe salah, angka non-finite/di luar rentang, atau field hilang menjadi `unanswered`, tidak pernah `benign`. `truncated` atau `errors` bukan clearance.

## Baseline lokal tepercaya

Tambahkan `"manifest": "/etc/mcp-audit/example.sha256.json"` pada site. Format object JSON: key path relatif berlabel, value SHA-256 lowercase 64 karakter:

```json
{"webroot/index.php": "0000000000000000000000000000000000000000000000000000000000000000"}
```

Hash nol hanya contoh format, bukan baseline valid aplikasi. Buat baseline dari salinan tepercaya di luar host tersangka, bukan otomatis dari file yang mungkin terinfeksi. Tool melaporkan `match`, `changed`, `new`. `missing` hanya dihitung jika scan lengkap tanpa error/truncation; `baseline_complete` menyatakan itu. Manifest tidak diunduh atau ditulis server; maksimum 2 MiB dan 1000 entri. Tidak memverifikasi signature maupun provenance baseline.

## Batas dan keamanan

Per scan: maksimum 1000 entry (termasuk direktori), 500 hasil, 2 MiB/file, 16 MiB pembacaan, kedalaman 32, deadline kooperatif 10 detik. Log maksimum 1 MiB terakhir, 500 event, 8192 byte/baris; format tidak didukung menghasilkan `unparsed_line`, tanpa isi. Triage opt-in memakai batas config yang sama untuk scan, ditambah `max_items`, `max_file_bytes`, dan `timeout_seconds`; respons HTTP maksimum 64 KiB. Subprocess fixed executable path, environment minimal, tanpa shell, output maksimum 64 KiB dan timeout 2 detik. Tidak ada opsi dari client untuk menaikkan batas. `truncated` dan `errors` wajib diperiksa; hasil kosong bukan clearance.

Traversal memakai descriptor direktori, `dir_fd`, `O_NOFOLLOW`, dan `fstat`; semua komponen path absolut diperiksa tanpa mengikuti symlink. FIFO/device/socket tidak dibaca. Race symlink tidak dialihkan ke file luar. Bukan sandbox: hard link, bind mount, rename direktori yang sudah terbuka, kernel/host berbahaya, dan filesystem network tidak dapat dibuktikan aman. Gunakan mount lokal tepercaya dan akun read-only terbatas. Deadline kooperatif tidak bisa menghentikan syscall filesystem yang macet; untuk SLA keras, gunakan supervisor/client process timeout. Bukan snapshot atomik: file berubah saat audit dapat menghasilkan hash tak konsisten.

Rule `PHP_TAG`, `PHP_DYNAMIC_EXEC`, `PHP_OBFUSCATION`, `PHP_REQUEST_INPUT` hanya indikator, sering ditemukan dalam PHP sah. Triage opsional memakai rule yang sama dan verdict model bukan bukti. Scan tidak mengekstrak archive, mendecode obfuscation, mengurai AST, atau menjalankan payload. File terlalu besar dilewati dengan truncation. Tidak ada verifikasi version/CVE WordPress/OJS, scanning DB, cleanup otomatis, karantina, atau pembuktian bebas rootkit. Tidak memindai seluruh disk secara diam-diam.

## Status verifikasi

Target rencana: Ubuntu terbaru dan CentOS Stream 9/10. **Belum diverifikasi pada OS tersebut**, maupun Python 3.11. Pengujian lokal saat ini: Debian 13, Python 3.14, SDK MCP 1.30.0 (unit test Linux juga dijalankan pada WSL Python 3.11). Unit test memakai fixture sementara inert, mencakup allowlist, config invalid, symlink file/direktori/ancestor, baseline, batas, payload disguised PHP, files_dir dan log tanpa rahasia, config triage/clamp, redaksi, key owner/mode/symlink/missing, dedup, `max_items`, file utuh, HTTP error tanpa body, refusal/nilai invalid menjadi `unanswered`, respons terbatas, dan redirect diblokir. Triage test men-stub transport; tidak ada request jaringan. Integration test benar-benar menjalankan subprocess stdio SDK, initialize, list tools, call tool, penolakan site tak dikenal, dan tool triage hanya terdaftar saat config triage ada. Tidak mengklaim audit production selesai.
