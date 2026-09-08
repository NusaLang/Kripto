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
```

`urai()` bongkar chunked transfer-encoding otomatis kalau ada.

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
cetak(kripto.baca_angka_le(dump, 0x1000, 4));  // int 4-byte little-endian di offset 0x1000
cetak(kripto.baca_angka_be(dump, 0x1000, 8));  // int 8-byte big-endian di offset yang sama
```

## Isi

- `kripto.ns` -- hex/url encode-decode, XOR (+ brute force kunci 1-byte), Vigenere, Caesar/ROT13, RSA (bignum beneran lewat plugin `crypto` bawaan nusa -- `make plugins` dulu di instalasi nusa-nya), konversi endian
- `web.ns` -- sesi HTTP (cookie jar, header custom, chunked decode)
- `forensik.ns` -- deteksi tipe file lewat magic bytes, ekstrak string tercetak, baca angka endian dari offset (buat RAM dump/binary analysis)

## Lisensi

MIT
