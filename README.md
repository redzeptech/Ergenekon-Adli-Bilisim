Ergenekon-Adli-Bilisim (Forensic Engine)
Ergenekon-Adli, Windows sistemlerindeki dijital ayak izlerini (Amcache ve Shimcache) analiz etmek, tehdit avcılığı (Threat Hunting) yapmak ve olay müdahalesi (Incident Response) süreçlerini hızlandırmak amacıyla geliştirilmiş modüler bir adli bilişim araştırma framework'üdür.

[!IMPORTANT]
HUKUKİ UYARI: Bu proje sadece EĞİTİM VE ARAŞTIRMA amaçlıdır. Geliştiriciler resmi bilirkişi değildir. Bu araç TCK 243-244 ve 6698 sayılı KVKK hükümlerine aykırı amaçlarla kullanılamaz. Tüm hukuki sorumluluk kullanıcıya aittir.

Temel Yetenekler
Artifact Correlation: Amcache.hve (Varlık) ve SYSTEM hive (Shimcache/Execution) verilerini çapraz sorgulayarak "Yürütme Kanıtı" oluşturur.

Sigma Engine: Şüpheli dosya yolları, çift uzantılar ve Masquerading (İsim değiştirme) tekniklerini otomatik tespit eder.

Evidence Integrity: Analiz edilen delilin ve üretilen raporun SHA-256 mühürlerini (report.hash) otomatik oluşturur.

Privacy-First: --mask parametresi ile analiz raporlarındaki Kullanıcı Adı, Path ve SID gibi kişisel verileri anonimleştirir.

Kullanım Kılavuzu
1. Standalone EXE (Önerilen)
Hiçbir kurulum gerektirmeden direkt çalıştırılabilir:
.\Ergenekon_Forensics_v1.exe -i "Amcache.hve" -s "SYSTEM" --mask --sigma --output-dir "case001"

2. Python CLI
Geliştiriciler ve özelleştirilmiş analizler için:
python amcache_evilhunter.py -i "Amcache.hve" -s "SYSTEM" --mask --sigma

Proje Yapısı (Working Core)
Gereksiz tüm bağımlılıklardan arındırılmış, operasyonel çekirdek yapı:

Ergenekon-Adli-Bilisim/
├── amcache_evilhunter.py   # Ana Giriş Noktası
├── ergenekon/              # Analiz Motoru ve Modüller
│   ├── core/               # Hive Parsing Mantığı
│   ├── parsers/            # Artifact Ayrıştırıcılar (Shim/Amcache)
│   ├── utils/              # Privacy (Masking), Logger, Integrity
│   └── exporters/          # JSON, CSV, Markdown Raporlama
├── binaries/               # Gerekli Statik Dosyalar
├── scripts/                # Build ve Otomasyon Betikleri
└── requirements.txt        # Minimal Bağımlılık Listesi

Hukuki Bağlam ve Metodoloji
Bu araç, bir siber olayın teknik analizinde "İnkar Edilemezlik" ve "Veri Bütünlüğü" ilkelerini esas alır.

Bağlam: Bir dosyanın sistemde bulunması (Amcache) ile çalıştırılması (Shimcache) arasındaki farkı bilimsel olarak raporlar.

Anlam: Sigma kuralları ile karmaşık veriyi "Anlamlı Bulgulara" dönüştürür.

Sonuç: SHA-256 mühürleme ile manipüle edilemez bir adli çıktı sunar.