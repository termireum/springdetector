# 🌱 SpringDetector

> Spring Boot Actuator & Endpoint Detector for Bug Bounty & Penetration Testing

SpringDetector adalah tool reconnaissance berbasis Go untuk mendeteksi endpoint Spring Boot yang terekspos pada sebuah domain dan seluruh subdomainnya secara otomatis.

---

## ✨ Fitur

- **Auto subdomain enumeration** via `subfinder`
- **1000+ endpoint wordlist** mencakup actuator, semicolon bypass, path traversal, dll
- **Spring Boot fingerprinting** dari response body & headers
- **Filter status code** dengan flag `-fc`
- **Concurrent scanning** — 5 subdomain paralel, masing-masing multi-thread
- **Bypass headers otomatis** — `X-Forwarded-For`, `X-Forwarded-Host`
- **Output ke file** untuk dokumentasi laporan
- **Grouped output** per subdomain untuk keterbacaan

---

## 📦 Requirements

- Go 1.20+
- [subfinder](https://github.com/projectdiscovery/subfinder) (opsional, untuk enum subdomain)

```bash
# Install subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

---

## 🔧 Installation

```bash
# Clone / copy source
git clone https://github.com/termireum/springdetector
cd springdetector

# Build
go build -o springdetector main.go

# (Opsional) Install global
sudo mv springdetector /usr/local/bin/
```

---

## 🚀 Usage

```
./springdetector -u <domain> -w <wordlist> [options]
```

### Options

| Flag | Default | Deskripsi |
|------|---------|-----------|
| `-u` | — | Target domain (wajib) |
| `-w` | — | Path ke wordlist (wajib) |
| `-fc` | — | Filter status code, misal `200` atau `200,403` |
| `-t` | `20` | Jumlah thread per subdomain |
| `-timeout` | `10` | HTTP timeout dalam detik |
| `-o` | — | Simpan hasil ke file |
| `-schemes` | `https,http` | Scheme yang diuji |
| `-H` | — | Custom header tambahan |
| `-no-subfinder` | `false` | Skip subfinder, scan domain langsung |
| `-v` | `false` | Verbose output |

---

## 📋 Contoh Penggunaan

**Scan penuh dengan subfinder:**
```bash
./springdetector -u example.com -w springboot_extended.txt
```

**Hanya tampilkan response 200:**
```bash
./springdetector -u example.com -w springboot_extended.txt -fc 200
```

**Tampilkan 200 dan 403:**
```bash
./springdetector -u example.com -w springboot_extended.txt -fc 200,403
```

**Skip subfinder, scan satu subdomain langsung:**
```bash
./springdetector -u admin.example.com -w springboot_extended.txt --no-subfinder
```

**Simpan hasil ke file:**
```bash
./springdetector -u example.com -w springboot_extended.txt -o hasil.txt
```

**Custom thread & timeout (untuk target lambat):**
```bash
./springdetector -u example.com -w springboot_extended.txt -t 10 -timeout 15
```

**Tambah custom header:**
```bash
./springdetector -u example.com -w springboot_extended.txt -H "Authorization:Bearer eyJ..."
```

**Kombinasi lengkap:**
```bash
./springdetector -u example.com -w springboot_extended.txt -fc 200 -t 30 -o hasil.txt
```

---

## 📤 Contoh Output

```
[~] Scanning https://admin.example.com (874 endpoints)
[~] Scanning https://api.example.com (874 endpoints)

[FOUND] https://admin.example.com
        Endpoint: /actuator/env
        Status:   200 | Size: 4821 bytes

[FOUND] https://admin.example.com
        Endpoint: /actuator/beans
        Status:   200 | Size: 18432 bytes

[FOUND] https://api.example.com
        Endpoint: /actuator
        Status:   403 | Size: 112 bytes

═══════════════════════════════════════════════════════
 SCAN COMPLETE
═══════════════════════════════════════════════════════
 Target       : example.com
 Subdomains   : 47
 Endpoints    : 874
 Filter       : [200]
 Findings     : 3

[+] Exposed Spring Boot Endpoints:

  https://admin.example.com
    200  /actuator/env
    200  /actuator/beans

  https://api.example.com
    403  /actuator
```

---

## 📁 Wordlist Coverage

Wordlist `springboot_extended.txt` mencakup:

| Kategori | Contoh |
|----------|--------|
| Actuator langsung | `/actuator`, `/actuator/env`, `/actuator/heapdump` |
| Alias pendek | `/env`, `/health`, `/metrics` |
| Management endpoints | `/management/health`, `/management/env` |
| Prefix path | `/api/actuator`, `/admin/actuator`, `/v1/actuator` |
| Semicolon bypass | `;/actuator/env`, `/actuator/;/env` |
| Path traversal | `/actuator/env/..`, `/..;/actuator/env` |
| Jolokia | `/actuator/jolokia`, `/jolokia/version` |
| Swagger / OpenAPI | `/swagger-ui.html`, `/v3/api-docs` |
| Prometheus | `/actuator/prometheus`, `/prometheus` |
| Redis / Cache | `/actuator/redis/info`, `/actuator/caches` |
| Spring Cloud | `/actuator/refresh`, `/actuator/gateway/routes` |
| K8s / GCloud | `/healthz`, `/readyz`, `/livez` |
| Backup extensions | `/actuator/env.bak`, `/actuator/env.json` |

---

## ⚙️ Cara Kerja

```
springdetector -u example.com -w wordlist.txt
       │
       ├─► subfinder → enumerate semua subdomain
       │
       ├─► untuk setiap subdomain:
       │     ├─► connectivity check (https dulu, lalu http)
       │     └─► probe semua endpoint dari wordlist (concurrent)
       │           ├─► cek status code
       │           ├─► fingerprint Spring Boot dari body & headers
       │           └─► filter status code jika -fc aktif
       │
       └─► tampilkan findings + summary
```

**Spring Boot terdeteksi jika:**
- Response body mengandung signature seperti `"status":"UP"`, `"_links"`, `Whitelabel Error Page`
- Header `Content-Type` mengandung `application/vnd.spring-boot.actuator`
- Endpoint termasuk kata kunci Spring Boot (`actuator`, `env`, `heapdump`, dll)
- Status 401/403 pada endpoint Spring Boot (auth-protected, tetap dilaporkan)

---

## ⚠️ Disclaimer

Tool ini dibuat untuk keperluan **bug bounty dan penetration testing yang sah** pada target yang telah mendapat izin. Penggunaan tool ini pada sistem tanpa izin melanggar hukum dan dapat dikenakan sanksi pidana berdasarkan **UU ITE** dan **UU PDP** di Indonesia.

Gunakan secara bertanggung jawab.

---

## 👤 Author

**termireum** — Independent Security Researcher & Penetration Tester
