# MAC Finder – Windows Network Device Locator

Windows üzerinde çalışan, MAC adresi girildiğinde yerel ağda bu cihazı bulup IP adresini ve diğer ağ bilgilerini gösteren hafif bir masaüstü programı.

## Özellikler

- Modern, sade ve koyu temalı masaüstü arayüzü (Tkinter)
- MAC adresi giriş alanı
- Otomatik yerel IP ve subnet algılama
- Ağ adaptörü seçimi
- Tara butonu
- Tarama ilerleme göstergesi
- Bulunan cihazlar tablosu
- Sonuçlarda satıra tıklayınca ayrıntıları göster
- MAC ve IP için hızlı kopyalama butonları
- CSV dışa aktarma

## Arayüz

- **Ağ Adaptörü**: Bağlı ağ adaptörleri otomatik olarak listelenir.
- **Hedef MAC Adresi**: Tarama yapılacak hedef MAC adresi girilir.
- **Test MAC'i**: `B8:AB:61:AB:DA:6E` (Cisco Meraki MS120-24P) varsayılan olarak ayarlıdır.

## Ağ Tarama Motoru

- Bilgisayarın aktif ağ adaptörlerini algıla (psutil ile)
- Yerel IP, netmask ve gateway bilgisini belirle
- İstenen MAC adresini normalize et
- Önce sistem ARP tablosunu kontrol et (`arp -a`)
- Ardından yerel subnet üzerinde cihaz keşfi yap (ping sweep)
- Scapy ile ARP taraması desteklenir (kurulu değilse otomatik fallback)
- Gereksiz port taraması yapılmaz
- Tarama yalnızca yerel ağda, bağlı adaptörde çalışır
- Hedef bulunduğunda tarama durdurulur

## Sonuç Bilgileri

Bulunan cihaz için:

- MAC Address
- IP Address
- Hostname
- Manufacturer / Vendor
- Gateway
- Network Interface
- Online / Offline
- İlk ve son görülme zamanı
- Bulunma yöntemi

Bilgi elde edilemezse "Bilinmiyor" olarak gösterilir.

## Meraki Desteği

Cisco Meraki API entegrasyonu için hazır bir altyapı bulunur.

- API anahtarı kullanıcı tarafından girilebilir.
- API anahtarı olmadan program normal yerel ağ taraması çalışmaya devam eder.
- API erişimi sağlanırsa cihazın ağdaki switch ve port bilgileri de gösterilebilir.

## Kurulum

```bash
pip install -r requirements.txt
python main.py
```

## Windows EXE Derleme

```bash
pip install pyinstaller
python -m PyInstaller --noconfirm --onefile --windowed main.py
```

veya `build.bat` dosyasını kullanın:

```bash
build.bat
```

## GitHub Actions

`.github/workflows/build.yml` workflow dosyası ile Windows üzerinde otomatik EXE derlenir.

## Çalışma

1. Uygulama açılır.
2. Varsayılan MAC adresi (`B8:AB:61:AB:DA:6E`) girilmektedir.
3. "Ağ Tarama Başlat" butonuna basılır.
4. Bulunan cihazların IP ve detayları görüntülenir.
5. CSV olarak dışa aktarılabilir.

## Tamamlanma Kriterleri

1. ✅ Uygulama açılıyor.
2. ✅ MAC adresi girilebiliyor.
3. ⚠️ Yerel ağ taraması çalışıyor (deneysel).
4. ✅ Bulunan cihazın IP ve MAC adresi eşleşiyor.
5. ✅ Hata durumları anlaşılır şekilde gösteriliyor.
6. ⚠️ Windows EXE oluşturuluyor (süreç).
7. ⏳ Kaynak kodu GitHub'a gönderiliyor.

## Lisans

MIT License
