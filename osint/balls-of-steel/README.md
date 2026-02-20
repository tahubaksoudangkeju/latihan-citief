## Judul Soal
Balls of Steel

## Deskripsi Soal
Terdapat sebuah video percakapan antara operator kapal perang (Rusia) dengan petugas penjaga pulau (Ukraina).<br>
Coba cari informasi mengenai **nama asli** (bukan versi inggrisnya) pulau tersebut beserta **koordinatnya**.<br>
Misal:
- Pulau Seruni
- Koordinat -5.8508058,110.5565372,3703 (ambil 2 digit setelah titik, jadi: -5.85,110.55)
- Maka flagnya: `CYB0X1{seruni,-5.85,110.55}`

*Catatan: flag tidak menggunakan spasi, tidak menggunakan huruf kapital, dan tidak perlu menggunakan kata **pulau** lagi

---
## Proof of Concept
- Cari di google dengan kata kunci `russian warship go f yourself`
- Maka akan ada banyak berita yang memberitakan kejadian tersebut
- Biasanya berita akan memberitahu nama pulau tersebut menggunakan versi inggris yaitu `snake island`
- Kemudian cari `snake island` di google maka akan muncul nama `zmiinyi Island`
- Terakhir cek koordinatnya di google maps, maka akan didapatkan hasil `45.2547169,30.2014321`
- Kemudian ambil 2 digit terakhir setelah titik

## Flag
CYB0X1{zmiinyi,45.25,30.20}