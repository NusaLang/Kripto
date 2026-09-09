# Kripto

Modul bantu buat CTF (crypto, web, forensik) di Nusantara.

## Pasang

```
nusa get github.com/NusaLang/Kripto
```

atau taruh manual di `nusantara_modules/Kripto/`.

## Pakai

```
buat kripto = impor("Kripto");
```

### Crypto

```
buat x = kripto.XorCipher("2a");
buat c = x.enkripsi(kripto.hex_encode("halo dari kripto"));
cetak(kripto.hex_decode(x.dekripsi(c)));

buat tebakan = kripto.xor_tebak_kunci_satu_byte(c);
cetak(tebakan.kunci, tebakan.teks);

buat v = kripto.Vigenere("kunci");
cetak(v.enkripsi("SERANG SAAT FAJAR"));

cetak(kripto.rot13("Halo CTF"));
cetak(kripto.caesar("Halo CTF", 3));

buat pub = kripto.Rsa(3233, 17);
buat priv = kripto.RsaPrivat(3233, 17, 2753);
buat cipher = pub.enkripsi(65);
cetak(priv.dekripsi(cipher));

// modulus RSA asli ratusan digit -- lewat teks, bukan angka
buat pub2 = kripto.Rsa("10000000000000000016800000000000000005031", "65537");
cetak(pub2.enkripsi("123456789012345678901234567890"));

cetak(kripto.hex_encode("data"));
cetak(kripto.hex_decode("64617461"));
cetak(kripto.url_encode("a=1&b=2"));
cetak(kripto.url_decode("a%3D1%26b%3D2"));  // "a=1&b=2"

cetak(kripto.hex_ke_angka("ff"));   // 255
cetak(kripto.angka_ke_hex(255));    // "ff"

cetak(kripto.modpow(4, 13, 497));   // 445
```

`hex_ke_angka`/`angka_ke_hex` konversi hex-string ke/dari SATU angka biasa (`"ff"` <-> `255`) -- beda sama `angka_ke_bytes_*` di bawah yang urusannya byte-string ber-endian.

`modpow` lewat arithmetic `angka` (double) biasa, jadi cuma aman buat modulus kecil (perkalian internalnya kepotong presisi kalau `mod` udah puluhan juta ke atas). Modulus RSA asli yang ratusan digit lewat kelas `Rsa`/`RsaPrivat` di atas (bignum beneran lewat plugin `crypto`), bukan `modpow()` langsung.

Helper tingkat rendah yang dipakai fungsi-fungsi di atas, jarang dipanggil langsung tapi tetep ada kalau perlu:

```
cetak(kripto.xor_byte(65, 42));         // 107 -- XOR dua byte (angka 0-255)
cetak(kripto.nilai_hex_digit(97));      // 10  -- nilai satu digit hex ('a' = kode 97)
cetak(kripto.cari("halo dunia", "dunia"));  // 5 -- index substring, -1 kalau gak ketemu
```

### Endian

```
cetak(kripto.angka_ke_bytes_be(305419896, 4));  // "12345678"
cetak(kripto.angka_ke_bytes_le(305419896, 4));  // "78563412"
cetak(kripto.bytes_ke_angka_be("12345678"));    // 305419896
cetak(kripto.bytes_ke_angka_le("78563412"));    // 305419896
cetak(kripto.balik_hex_byte("12345678"));       // "78563412"
```

`angka_ke_bytes_*` selalu zero-pad ke `panjang_byte` byte -- `angka_ke_bytes_be(255, 2)` jadi `"00ff"`, bukan `"ff"`.

### Web

```
buat s = kripto.SesiHttp("127.0.0.1", 8080);
s.atur_header("X-Kunci", "rahasia");
buat r = s.get("/login");
cetak(r["status"], r["tubuh"], s.cookie_teks());

buat r2 = s.post("/login", "user=admin&pass=admin");
cetak(r2["status"], r2["tubuh"]);
```

`urai()` (dipanggil otomatis dari `get`/`post`) bongkar chunked transfer-encoding sendiri kalau ada, lewat `urai_chunked` -- bisa juga dipanggil langsung kalau udah megang body chunked mentah dari tempat lain:

```
buat mentah = "5\r\nhalo \r\n5\r\ndunia\r\n0\r\n\r\n";
cetak(kripto.urai_chunked(mentah));  // "halo dunia"
```

### Forensik

```
buat data = baca_file("file.bin");
cetak(kripto.deteksi_tipe_file(data));
cetak(kripto.ekstrak_string(data, 4));
cetak(kripto.cocok_di(data, 0, "89504e470d0a1a0a"));
```

Buat baca angka mentah dari dump biner (RAM dump, dst) -- `baca_angka_be`/`baca_angka_le` baca `panjang_byte` byte langsung dari `data` di posisi `offset` (bukan dari hex string kayak fungsi di atas, dari isi file/dump aslinya):

```
buat dump = baca_file("memory.dmp");
cetak(kripto.baca_angka_le(dump, 4096, 4));  // int 4-byte little-endian di offset 4096
cetak(kripto.baca_angka_be(dump, 4096, 8));  // int 8-byte big-endian di offset yang sama
```

**Catatan:** bahasa ini gak punya literal hex (`0x1000`) -- tulis angka desimal langsung, atau hitung dulu (`4096` = `0x1000`).

Baca angka dari BELAKANG buffer (footer/panjang/CRC yang biasanya nempel di akhir file) -- `offset`-nya tinggal dihitung mundur dari `panjang(data)`, gak ada argumen offset-negatif:

```
buat n_byte = 4;
buat angka_terakhir = kripto.baca_angka_le(data, panjang(data) - n_byte, n_byte);
```

`angka_ke_bytes_be/le` di atas balikin TEKS HEX (`"12345678"`), bukan byte mentah -- kalau mau digabung ke buffer yang bakal dibaca `baca_angka_*`, `kripto.hex_decode()` dulu:

```
buat data = "ABCD" + kripto.hex_decode(kripto.angka_ke_bytes_le(1337, 4));
cetak(kripto.baca_angka_le(data, panjang(data) - 4, 4));  // 1337
```

Bikin payload overflow (padding + alamat return yang di-pack) -- `byte_padding` angka 0-255 (65 = 'A', 144 = NOP), bukan teks, karena bahasa ini gak punya escape `\xNN` buat byte mentah di string literal:

```
buat payload = kripto.bikin_payload(40, 65, 82539765486, 8, "le");
tulis_file("payload.bin", payload);
```

## Isi

- `kripto.ns` -- hex/url encode-decode, XOR (+ brute force kunci 1-byte), Vigenere, Caesar/ROT13, RSA (bignum beneran lewat plugin `crypto`, udah kebundel di binary rilis nusa), konversi endian
- `web.ns` -- sesi HTTP (cookie jar, header custom, chunked decode)
- `forensik.ns` -- deteksi tipe file lewat magic bytes, ekstrak string tercetak, baca angka endian dari offset (buat RAM dump/binary analysis), bikin payload overflow (padding + alamat)

## Lisensi

MIT
