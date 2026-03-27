# Ergenekon-Adli-Bilisim (Forensic Engine)

Ergenekon-Adli, Windows sistemlerindeki dijital ayak izlerini (Amcache ve Shimcache) analiz etmek, tehdit avciligi (Threat Hunting) yapmak ve olay mudahalesi (Incident Response) sureclerini hizlandirmak amaciyla gelistirilmis moduler bir adli bilisim arastirma framework'udur.

> [!IMPORTANT]
> **HUKUKI UYARI:** Bu proje sadece EGITIM VE ARASTIRMA amaclidir. Gelistiriciler resmi bilirkisi degildir. Bu arac TCK 243-244 ve 6698 sayili KVKK hukumlerine aykiri amaclarla kullanilamaz. Tum hukuki sorumluluk kullaniciya aittir.

## Temel Yetenekler

- **Artifact Correlation:** Amcache.hve (Varlik) ve SYSTEM hive (Shimcache/Execution) verilerini capraz sorgulayarak "Yurutme Kaniti" olusturur.
- **Sigma Engine:** Supheli dosya yollari, cift uzantilar ve Masquerading (isim degistirme) tekniklerini otomatik tespit eder.
- **Evidence Integrity:** Analiz edilen delilin ve uretilen raporun SHA-256 muhurlerini (`report.hash`) otomatik olusturur.
- **Privacy-First:** `--mask` parametresi ile analiz raporlarindaki Kullanici Adi, Path ve SID gibi kisisel verileri anonimlestirir.

## Kullanim Kilavuzu

### 1) Standalone EXE (Onerilen)

Hicbir kurulum gerektirmeden direkt calistirilabilir:

```powershell
.\Ergenekon_Forensics_v1.exe -i "Amcache.hve" -s "SYSTEM" --mask --sigma --output-dir "case001"
```

### 2) Python CLI

Gelistiriciler ve ozellestirilmis analizler icin:

```powershell
python amcache_evilhunter.py -i "Amcache.hve" -s "SYSTEM" --mask --sigma
```

## Proje Yapisi (Working Core)

Gereksiz tum bagimliliklardan arindirilmis, operasyonel cekirdek yapi:

```text
Ergenekon-Adli-Bilisim/
├── amcache_evilhunter.py   # Ana Giris Noktasi
├── ergenekon/              # Analiz Motoru ve Moduller
│   ├── core/               # Hive Parsing Mantigi
│   ├── parsers/            # Artifact Ayristiricilar (Shim/Amcache)
│   ├── utils/              # Privacy (Masking), Logger, Integrity
│   └── exporters/          # JSON, CSV, Markdown Raporlama
├── binaries/               # Gerekli Statik Dosyalar
├── scripts/                # Build ve Otomasyon Betikleri
└── requirements.txt        # Minimal Bagimlilik Listesi
```

## Hukuki Baglam ve Metodoloji

Bu arac, bir siber olayin teknik analizinde "Inkar Edilemezlik" ve "Veri Butunlugu" ilkelerini esas alir.

- **Baglam:** Bir dosyanin sistemde bulunmasi (Amcache) ile calistirilmasi (Shimcache) arasindaki farki bilimsel olarak raporlar.
- **Anlam:** Sigma kurallari ile karmasik veriyi "Anlamli Bulgulara" donusturur.
- **Sonuc:** SHA-256 muhurlleme ile manipule edilemez bir adli cikti sunar.

- ## 👥 Katkıda Bulunanlar (Contributors)

- **Cristian Souza** (@cristianzsh) - *Original Author & Core Logic of Amcache-EvilHunter.*
- **[Senin Kullanıcı Adın]** (@[redzeptech]) - *Refactoring, Forensic Integrity (Hashing), Multi-Artifact Correlation, and PII Masking layers.*

> Bu proje, açık kaynak topluluğunun gücüyle ve etik değerlere (attribution) sadık kalınarak geliştirilmiştir.
