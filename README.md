# Kripto

Modul bantu buat CTF (crypto, web, forensik) di Nusantara.

## Pasang

```
nusa get git:github.com/NusaLang/Kripto
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

cetak(kripto.hex_encode("data"));
cetak(kripto.hex_decode("64617461"));
cetak(kripto.url_encode("a=1&b=2"));
```

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

## Isi

- `kripto.ns` -- hex/url encode-decode, XOR (+ brute force kunci 1-byte), Vigenere, Caesar/ROT13, RSA
- `web.ns` -- sesi HTTP (cookie jar, header custom, chunked decode)
- `forensik.ns` -- deteksi tipe file lewat magic bytes, ekstrak string tercetak

## Lisensi

MIT
