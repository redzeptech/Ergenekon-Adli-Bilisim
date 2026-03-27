<<<<<<< HEAD
# Ergenekon-Adli-Bilisim

## Vitrini Kur
Ergenekon-Adli-Bilisim, bir **Forensic Engine** olarak tasarlanmış; özellikle **Amcache** ve **Shimcache** kayıtlarını korelasyonlayarak yürütme/iz bulgularını birlikte değerlendirir.

## Hukuki Kalkan (Kritik)
**Bu proje sadece eğitim amaçlıdır, bilirkişi raporu yerine geçmez.**

Bu araç TCK 243–244 kapsamında hukuka aykırı amaçlarla kullanılamaz. 6698 sayılı **KVKK** kapsamında, elde edilen kişisel verilerin anonimleştirilmesi/maskeleme kullanıcının sorumluluğundadır.

## Kullanım Kılavuzu

### .exe (Standalone)
Tek parça yürütülebilir dosya: `dist/Ergenekon_Forensics_v1.exe`

Amcache analizi (PII maskeleme + SHA-256 mühürleme):
```powershell
.\dist\Ergenekon_Forensics_v1.exe -i "C:\evidence\Amcache.hve" --mask --output-dir "output" --sigma
```

Amcache + Shimcache korelasyonu (SYSTEM hive):
```powershell
.\dist\Ergenekon_Forensics_v1.exe -i "C:\evidence\Amcache.hve" -s "C:\evidence\SYSTEM" --authorized-use-confirm --mask --sigma
```

### Python CLI (Çalışır çekirdek)
Modül olarak:
```powershell
python -m ergenekon.cli.amcache_cli -i "C:\evidence\Amcache.hve" --mask --output-dir "output" --sigma
```

Varsayılan giriş betiği:
```powershell
python amcache_evilhunter.py -i "C:\evidence\Amcache.hve" --mask --output-dir "output"
```

## Teknik Özellikler
- `Sigma kuralları`: Sigma-benzeri kurallarla şüpheli kayıt ve yürütme tespiti.
- `Masquerading tespiti`: isim uyuşmazlığı/maskeleme benzeri davranış kontrolleri.
- `SHA-256 mühürleme`: rapor çıktıları için SHA-256 bütünlük manifesti (örn. `report.hash`) ve zincir of custody doğrulaması.
- `PII maskeleme`: `--mask` ile KVKK uyumuna yönelik kişisel verilerin maskeleme/anonimleştirme.

## Dosya Yapısı
Temizlediğimiz “yalın ve sert” çalışma çekirdeği:
```text
Ergenekon-Adli-Bilisim/
├── amcache_evilhunter.py
├── uareport.py
├── binaries/
├── ergenekon/
│   ├── cli/
│   ├── core/
│   ├── parsers/
│   ├── exporters/
│   └── utils/
├── scripts/
│   └── build_exe.py
└── requirements.txt, pyproject.toml
```

<!--
Windows için **forensictools** tabanlı Inno Setup paketinin Türkçe yerelleştirilmiş sürümü. Üst kaynak: [cristianzsh/forensictools](https://github.com/cristianzsh/forensictools).

## Yasal Uyarı (Disclaimer)

UYARI: Bu yazılım, TCK 243 (Bilişim sistemine yetkisiz girme) ve TCK 244 (Sistemi engelleme, bozma, verileri yok etme veya değiştirme) maddelerine aykırı amaçlarla kullanılamaz. 6698 sayılı KVKK kapsamında, elde edilen kişisel verilerin anonimleştirilmesi kullanıcının sorumluluğundadır. Bu araç sadece adli makamlar, siber güvenlik araştırmacıları ve sistem yöneticileri tarafından "meşru müdafaa" veya "olay müdahalesi" kapsamında kullanılmak üzere tasarlanmıştır.

Ayrıntılar için: [`DISCLAIMER.md`](DISCLAIMER.md)

## Yasal uyarı ve sorumluluk reddi

**DİKKAT — yalnızca bilgilendirme ve eğitim:** Bu depo ve içerdiği materyaller **hukuki danışmanlık değildir**; yazar(lar) **bilirkişi sıfatı taşımaz** ve **avukatlık / hukuki mütalaa sunmaz**. İçerik, araçların **yasal çerçevede** ve **yetkili kullanım** ile ilişkilendirilmesi için genel **bilgilendirme** ve **öğrenme** amaçlıdır.

Bu yazılımların kullanımı; **yetkisiz veri erişimi** gibi durumlarda **6698 sayılı KVKK** ve **5237 sayılı Türk Ceza Kanunu (TCK)** kapsamındaki **bilişim suçları** başta olmak üzere ilgili mevzuata tabi olabilir — bu ifadeler özet **uyarı** niteliğindedir, yorum veya tavsiye değildir. Kullanımdan doğan **tüm sorumluluk kullanıcıya** aittir; geliştiriciler ve katkı verenler **kötüye veya yetkisiz kullanımdan** doğan sonuçlardan sorumlu tutulamaz.

Ayrıntılı lisans ve İngilizce “AS IS” hükümleri için [`LICENSE`](LICENSE) dosyasına bakın.

### Referans mevzuat özeti (bağlayıcı yorum değildir)

Aşağıdaki madde numaraları **özet referans** içindir; güncel metin ve içtihat için **Resmî Gazete** ve **mevzuat veri tabanları** esas alınmalıdır. Bu liste **eksik** olabilir; özel durumda **hukuk profesyoneline** başvurulması gerekir.

| Alan | Örnek düzenleme | Kısa not |
|------|------------------|----------|
| Kişisel veri | **6698 sayılı KVKK** (ör. veri işleme şartları, veri güvenliği, ilgili kişi hakları) | Adli kopyalarda bile **kimlik, kullanıcı adı, yol, SID** vb. **kişisel veya tanımlanabilir** olabilir; paylaşım öncesi **maskeleme / sözdeanonimleştirme** ve **kurum politikaları** uygulanmalıdır. |
| Bilişim suçları (TCK) | **m. 243** — Bilişim sistemine girme | Yetkisiz veya hukuka aykırı **sisteme erişim** |
| | **m. 244** — Sistemdeki verileri bozma / engelleme | Veri veya sistemin **bütünlüğü** |
| | **m. 245** — Banka / kredi kartı ile ilgili suçlar | Kart verileriyle ilgili **özel** düzenlemeler |
| | **m. 246** — Verileri hukuka aykırı verme veya ele geçirme | **Yetkisiz elde etme / ifşa** |
| | **m. 124–125** vb. — Özel hayatın gizliliği | İletişimin **dinlenmesi / kaydı** gibi eylemlerle ilişkili olabilir |
| Usul / yetki | **CMK** ve özel kanunlar kapsamında **yetkili makam** kararı | Delil toplama ve **zincir of custody** kurum içi prosedürlere tabidir |

**KVKK uyumu için teknik önlem:** Paket içi `ergenekon.utils.masker.mask_kvkk_identifiers` ve CLI `--mask` bayrakları **yardımcı araçtır**; **Veri Sorumlusu** yükümlülüklerinin yerine geçmez.

### Maskeleme ve paylaşım

- Test, eğitim veya üçüncü tarafla paylaşımda **gerçek kullanıcı adı, tam yol, SID, IP** gibi tanımlayıcıları **açık bırakmayın**.
- Hash tabanlı kısaltmalar **çakışma** ve **yeniden kimliklendirme (re-identification)** riskini tamamen ortadan kaldırmaz; hassas ortamlarda **ek kontroller** uygulayın.

## Dizin düzeni

```text
Ergenekon-Adli-Bilisim/
├── binaries/               # Statik analiz aracı ikilileri / yardımcı dosyalar
├── docs/help/              # Yardım HTML (depodaki asıl kopya)
├── ergenekon/              # Python paketi (modüler çekirdek)
│   ├── cli/                # amcache-evilhunter, uareport giriş noktaları
│   ├── core/               # Registry/Amcache parse motoru ve istisnalar
│   ├── parsers/            # Windows artifact ayrıştırıcıları
│   ├── exporters/          # JSON, CSV, Markdown/PDF raporlama
│   └── utils/              # privacy.py, logger.py, threat intel, yardımcılar
├── ftools/                 # Inno öncesi: ikililer, sendto+, imgs, help kopyası
├── legal/                  # KVKK ve TCK uyum belgeleri
├── output/                 # Derlenen kurulum (.gitignore)
├── pyproject.toml          # ergenekon-adli paket tanımı
├── scripts/                # prepare-ftools.ps1
├── src/                    # forensictools.iss + *.iss parçaları (Windows paketleyici)
├── tests/                  # Maskelenmiş örnek verilerle testler
└── tools/amcache-evilhunter/   # Amcache CLI (ergenekon kullanır)
```

| Ne nerede | Açıklama |
|-----------|----------|
| `src/forensictools.iss` | Ana betik; `MySrcDir` → `..\ftools` |
| `src/*/*.iss` | Araç başına kurulum parçaları |
| `ergenekon/` | Yeniden kullanılabilir analiz kütüphanesi (`pip install -e .`) |
| `docs/help/help.html` | Yardım (kurulumda kullanılacak metin; çoğu bölüm özgün İngilizce) |
| `ftools/` | Üst projedeki yapıyla aynı klasör ağacı (`binaryanalysis\capa`, `sendto+`, `imgs`, …) |

## Derleme akışı

1. [Inno Setup 6](https://jrsoftware.org/isdl.php) kurulu olsun.
2. `ftools` içine forensictools’tan gelen tüm araç dosyalarını yerleştirin.
3. Yardım dosyasını senkronlayın:

   ```powershell
   .\scripts\prepare-ftools.ps1
   ```

4. `src\forensictools.iss` dosyasını Inno ile derleyin. Çıktı: `output\ErgenekonAdliBilisim_1.3_setup.exe` (sürüm betikteki `#define` ile aynıdır).

**Not:** Kurulum simgesi `ftools\imgs\forensictools.ico` yolundan okunur; bu dosya derleme anında da gerekir.

## Python paketi ve AmCache-EvilHunter

Depo kökünde düzenlenebilir kurulum (önerilen):

```powershell
pip install -r requirements.txt
# veya doğrudan: pip install -e .
```

- **Paket adı:** `ergenekon-adli` (içe aktarma: `import ergenekon`).
- **Konsol komutları (PATH):** `amcache-evilhunter -i Amcache.hve` · `uareport -d C:\evidence\Users`
- **Modül olarak:** `python -m ergenekon.cli.amcache_cli` · `python -m ergenekon.cli.userassist_cli`
- **API:** `from ergenekon import AmcacheEngine` (veya `ergenekon.core`) → `AmcacheEngine(path).run()`
- **Eski betik yolu:** `python tools\amcache-evilhunter\amcache-evilhunter.py ...` (depo kökünü `sys.path`’e ekler)

### Hızlı Kullanım Senaryoları

1) Varsayılan çıktı dizini (`output/`) ile maskeleme:

```powershell
python -m ergenekon.cli.amcache_cli -i Amcache.hve --mask --output-dir output
```

Bu komut `output/` altında `amcache.json`, `amcache.csv` ve `report.md` üretir.

2) Özel dosya isimleri ile çıktı alma:

```powershell
python -m ergenekon.cli.amcache_cli -i Amcache.hve --mask --json output\case01.json --csv output\case01.csv --report-md output\case01_report.md
```

3) Tarih aralığı filtresi ile analiz:

```powershell
python -m ergenekon.cli.amcache_cli -i Amcache.hve --start 2026-01-01 --end 2026-01-31 --mask --output-dir output
```

4) Amcache + SYSTEM (Shimcache korelasyonu) ile analiz:

```powershell
python amcache_evilhunter.py -i Amcache.hve -s SYSTEM --authorized-use-confirm --vt --mask
```

- `-i`: Amcache dosyasi (varlik/iz kaydi)
- `-s`: SYSTEM hive dosyasi (Shimcache/AppCompatCache yurutmeye dayali kanit)
- `--authorized-use-confirm`: `--system` kullaniminda zorunlu yetkili kullanim onayi (TCK 243)
- `--mask`: KVKK uyumu icin yol/kullanici verilerini maskeleme

### Islem Sirasi (Flow)

`amcache_cli` islem akisi KVKK ve Sigma uyumu icin su sirayla calisir:

1) Hive parse + temel filtreler  
2) Sigma kurallari ile tarama (`--sigma`)  
3) Shimcache parse + Amcache path korelasyonu (`-s`, `--system`)  
4) PII maskeleme (`--mask`)  
5) Cikti uretimi (`JSON`, `CSV`, `report.md`) + SHA-256 hash manifest (`report.hash`)

Bu sira, maskelemenin Sigma regex eslesmelerini bozmasini engellemek icin korunur.

### Parametre Özeti (Amcache CLI)

| Parametre | Açıklama | Örnek |
|---|---|---|
| `-i`, `--input` | Analiz edilecek `Amcache.hve` dosya yolu (zorunlu) | `-i C:\evidence\Amcache.hve` |
| `-s`, `--system` | `SYSTEM` hive yolu (Shimcache/AppCompatCache korelasyonu) | `-s C:\evidence\SYSTEM` |
| `--authorized-use-confirm` | `--system` ile zorunlu yetkili kullanim onayi | `--authorized-use-confirm` |
| `--mask` | PII alanlarını (`Username`, `ComputerName`, `Path`, `FilePath`) maskeler | `--mask` |
| `--output-dir` | Varsayılan çıktı dizini (`amcache.json`, `amcache.csv`, `report.md`) | `--output-dir output` |
| `--json` | JSON çıktı dosya yolu (özel ad/yol) | `--json output\case01.json` |
| `--csv` | CSV çıktı dosya yolu (özel ad/yol) | `--csv output\case01.csv` |
| `--report-md` | Markdown rapor dosya yolu (özel ad/yol) | `--report-md output\case01_report.md` |
| `--start` | Başlangıç tarihi filtresi (`YYYY-MM-DD`) | `--start 2026-01-01` |
| `--end` | Bitiş tarihi filtresi (`YYYY-MM-DD`) | `--end 2026-01-31` |
| `--format` | Stdout biçimi: `table`, `json`, `both` | `--format both` |

`tools\amcache-evilhunter\requirements.txt` yalnızca bağımlılık listesidir; tam paket için kökten `pip install -e .` kullanın.

### Ornek cikti (Shimcache korelasyonu)

`-s/--system` ile calistiginda, Amcache kayitlari Shimcache path eslesmesi ile
`ExecutionStatus: VERIFIED` olarak etiketlenir ve `ShimcacheLastModified` alani eklenir.

Ornek JSON kaydi:

```json
{
  "Name": "evil.exe",
  "FilePath": "C:\\Users\\[ANONYMIZED]\\AppData\\Roaming\\evil.exe",
  "SHA-1": "1234abcd...",
  "RecordDate": "2026-03-25T10:14:22",
  "ExecutionStatus": "VERIFIED",
  "ShimcacheLastModified": "2026-03-25T10:13:57"
}
```

Ornek timeline kaydi:

```json
{
  "timestamp": "2026-03-25T10:13:57",
  "source": "Shimcache",
  "path": "C:\\Users\\[ANONYMIZED]\\AppData\\Roaming\\evil.exe",
  "sha1": "",
  "status": "VERIFIED"
}
```

Markdown raporda:
- `## Execution Timeline` bolumu olaylari kronolojik sirada listeler.
- `## Verified Executions` bolumu sadece `VERIFIED` kayitlari ozetler.

### Test / paylaşım: KVKK uyumlu maskeleme

`ergenekon.utils.masker` modülü, gerçek kullanıcı adı, IP ve SID gibi verileri **sözdeanonimleştirmek** için hash tabanlı kısa takma değerler üretir (aynı girdi → aynı maske).

```python
from ergenekon.utils.masker import (
    mask_sensitive_data,
    mask_ip,
    mask_sid,
    mask_users_folder_in_path,
    mask_ips_in_text,
    mask_sids_in_text,
    mask_structure,
)

mask_sensitive_data("gercek.kullanici")  # SHA-256 hex[:10]
mask_ip("192.168.1.10")
mask_sid("S-1-5-21-1234567890-1234567890-1234567890-1001")
mask_users_folder_in_path(r"C:\Users\Ayse\Desktop\dosya.exe")
mask_structure({"username": "x", "ip": "10.0.0.1", "nested": {"sid": "S-1-5-32-544"}})
```

Bu araçlar **hukuki uyumluluk garantisi vermez**; paylaşım öncesi kurum içi KVKK süreçlerine uygun kullanın.

## Önceki düzenlemeler (özet)

- TestDisk + PhotoRec tek bileşen; kırılabilir TestDisk kısayolları kaldırıldı (PhotoRec GUI korundu).
- Kaldırma sırasında hatalı `utilities\testdisk` PATH satırı düzeltildi.
- Çıktı klasörü `output\` olarak ayrıldı.

## Lisans

Üçüncü taraf araçların lisansları kendi paketlerindedir; bu depo üst projenin lisansına tabi katman içerir.
-->
=======
# Ergenekon-Adli-Bilisim
>>>>>>> a8adf8528107b91e30df0712bb21a9d837c177d6
