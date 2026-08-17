# Aku Cinta VPN

Program ini merupakan VPN **point-to-point Layer 3** untuk Linux yang dibuat dengan menggunakan Go. Program  akan membaca paket IPv4 dari antarmuka TUN,
mengenkripsi dan mengautentikasinya, lalu mengirimkannya ke peer melalui UDP.
Pada arah sebaliknya, datagram UDP diverifikasi, didekripsi, dan ditulis kembali
ke antarmuka TUN sebagai trafik jaringan biasa.

## Fitur penting

- Tunnel Layer 3 berbasis antarmuka TUN native Linux (`IFF_TUN | IFF_NO_PI`).
- Komunikasi dua arah melalui satu peer UDP dengan alur
  `TUN -> enkripsi -> UDP` dan `UDP -> autentikasi/dekripsi -> TUN`.
- Enkripsi terautentikasi untuk seluruh paket IPv4 menggunakan
  ChaCha20-Poly1305 AEAD.
- Pre-shared key (PSK) 256-bit yang dibuat dengan `crypto/rand`, disimpan sebagai
  64 karakter heksadesimal dengan permission `0600`, dan tidak ditanam di kode.
- Nonce unik 96-bit yang terdiri dari prefix sesi acak 32-bit dan sequence number
  64-bit yang terus meningkat.
- Header protokol ikut diautentikasi sebagai Additional Authenticated Data (AAD),
  sehingga perubahan pada metadata paket juga terdeteksi.
- Proteksi replay dengan sliding window 64 paket. Paket duplikat atau terlalu
  lama, paket dari alamat peer yang tidak dikenal, paket rusak, dan paket yang
  gagal autentikasi akan dibuang.
- Validasi paket IPv4 dan MTU konservatif bawaan sebesar 1300 byte.
- Logging informatif serta opsi `--verbose` untuk melihat alur paket saat
  debugging.
- Skrip demonstrasi network namespace yang menempatkan dua endpoint di subnet
  underlay berbeda dan menguji ping serta transfer file 5 MB melalui VPN.

## Algoritma kriptografi

Proyek ini menggunakan **ChaCha20-Poly1305 AEAD** dari paket resmi Go
`golang.org/x/crypto/chacha20poly1305`, dengan PSK 256-bit.

Algoritma ini dipilih karena:

- memberikan kerahasiaan dan integritas sekaligus; ciphertext yang diubah atau
  dibuat tanpa kunci yang benar akan gagal diautentikasi;
- cepat dan konsisten pada perangkat yang tidak memiliki akselerasi AES;
- memiliki implementasi library yang matang sehingga proyek tidak membuat
  primitive kriptografi sendiri; dan
- cocok untuk protokol berbasis paket karena setiap datagram dapat dienkripsi dan
  diautentikasi secara independen.

Setiap paket memakai nonce 12 byte yang dibentuk dari prefix sesi acak dan
sequence number. Header 16 byte dikirim dalam bentuk plaintext agar dapat
diparsing, tetapi tetap dilindungi sebagai AAD. Poly1305 menambahkan tag
autentikasi 16 byte, sehingga total overhead protokol adalah 32 byte per paket.

Kedua endpoint harus menggunakan file PSK yang sama. Simpan dan kirimkan PSK
melalui saluran yang aman; jangan pernah memasukkannya ke Git.

## Persyaratan

- Linux dengan dukungan TUN (`/dev/net/tun`)
- Go 1.22 atau yang lebih baru
- `make` dan `iproute2` (perintah `ip`)
- akses `root` atau capability `CAP_NET_ADMIN` untuk membuat dan mengatur TUN
- `python3`, `curl`, `sha256sum`, dan `dd` hanya untuk pengujian transfer file

## Cara menjalankan program

### Demo lokal dengan network namespace

Build binary, jalankan unit test, dan buat PSK:

```bash
make build
make test
make key
```

`make key` membuat `vpn.key` secara aman dan akan gagal jika file tersebut sudah
ada agar kunci yang ada tidak tertimpa.

Buat topologi demo dengan dua endpoint pada subnet underlay yang berbeda:

```bash
sudo make setup-demo
sudo ./scripts/test-underlay.sh
```

Jalankan endpoint A pada terminal pertama:

```bash
sudo ./scripts/run-a.sh
```

Lalu jalankan endpoint B pada terminal kedua:

```bash
sudo ./scripts/run-b.sh
```

Saat kedua proses menampilkan `VPN tunnel ready`, uji overlay dari terminal
ketiga:

```bash
sudo ./scripts/test-ping.sh
sudo ./scripts/test-file-transfer.sh
```

Tambahkan `--verbose` untuk melihat log per paket, misalnya
`sudo ./scripts/run-a.sh --verbose`. Hentikan masing-masing endpoint dengan
`Ctrl+C`, lalu hapus topologi demo:

```bash
sudo make clean-demo
```

### Menjalankan pada dua host Linux

Build program dan buat satu PSK pada salah satu host:

```bash
make build
./bin/aku-cinta-vpn --generate-key vpn.key
```

Salin binary dan `vpn.key` ke host kedua melalui saluran yang aman. Contoh
konfigurasi berikut mengasumsikan:

| Endpoint | IP underlay | IP VPN |
| --- | --- | --- |
| A | `192.168.10.2` | `10.8.0.1/24` |
| B | `192.168.20.2` | `10.8.0.2/24` |

Pastikan kedua alamat underlay dapat saling dijangkau dan UDP port `51820`
diizinkan oleh firewall. Jalankan pada endpoint A:

```bash
sudo ./bin/aku-cinta-vpn \
  --tun tun0 \
  --tun-ip 10.8.0.1/24 \
  --listen 192.168.10.2:51820 \
  --peer 192.168.20.2:51820 \
  --key vpn.key \
  --mtu 1300
```

Jalankan pada endpoint B dengan posisi alamat dibalik:

```bash
sudo ./bin/aku-cinta-vpn \
  --tun tun0 \
  --tun-ip 10.8.0.2/24 \
  --listen 192.168.20.2:51820 \
  --peer 192.168.10.2:51820 \
  --key vpn.key \
  --mtu 1300
```

Uji tunnel dari endpoint A:

```bash
ping 10.8.0.2
```

Daftar opsi selengkapnya dapat dilihat dengan:

```bash
./bin/aku-cinta-vpn --help
```

## Pengujian dan pemeriksaan kode

```bash
make test
make vet
```