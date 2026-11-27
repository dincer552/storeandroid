# MAC Finder Pro – Local Network Device Inventory & Locator

Windows 10/11 üzerinde çalışan, yerel IPv4 subnet'inde cihaz keşfeden ve MAC adresini anahtar kabul ederek SQLite envanteri tutan hafif masaüstü uygulaması.

## Özellikler
- Koyu temalı modern Tkinter arayüzü
- Aktif ağ adaptörü seçimi ve otomatik yerel subnet algılama
- Tek MAC arama ve tüm yerel subnet'i tarama
- MAC, IP, hostname, vendor, gateway, interface, discovery method, first/last seen ve online/offline durumu
- SQLite ile kalıcı envanter; özel cihaz adı ve not alanları
- Cihaz arama/filtreleme, ayrıntı penceresi ve MAC/IP kopyalama
- CSV ve JSON envanter dışa aktarma
- Yeni cihaz algılandığında isteğe bağlı sesli uyarı
- Windows reverse-DNS/NetBIOS hostname çözümleme denemesi
- Opsiyonel Scapy ARP keşfi; Scapy/Npcap yoksa OS ARP + ping fallback
- İsteğe bağlı Meraki Dashboard API ile switch port status'larında client MAC arama

## Kurulum
Python 3.11+ gerekir.

\`\`\`powershell
python -m pip install -r requirements.txt
python main.py
\`\`\`

Temel çalışma için yalnızca psutil gerekir. Scapy'yi kaynak koddan çalıştırmak veya Scapy ile EXE üretmek isterseniz ayrıca:

\`\`\`powershell
python -m pip install -r requirements-scapy.txt
\`\`\`

Windows üzerinde Scapy Layer-2 ARP için Npcap ve uygun yetkiler gerekebilir. Scapy veya Npcap yoksa uygulama otomatik olarak ARP önbelleği ve ping+ARP yöntemine döner.

## EXE üretimi
\`build.bat\` dosyasını çalıştırın. Çıktı: \`dist\\MACFinder.exe\`.

GitHub Actions Windows üzerinde:
1. Python dosyalarını compile eder.
2. Offline unit testlerini çalıştırır.
3. \`dist/MACFinder.exe\` üretir ve dosyanın varlığını/boyutunu doğrular.
4. \`MACFinder-Windows\` artifact'ini yükler.
5. \`v*\` etiketi push edilirse GitHub Release oluşturur.

## Envanter veritabanı
Varsayılan konum:
- Windows: \`%LOCALAPPDATA%\\MACFinderPro\\inventory.db\`
- Diğer platformlarda: \`~/.local/share/MACFinderPro/inventory.db\`

MAC adresi birincil anahtardır. Tek MAC araması veya tam subnet taraması sonrası kayıtlar güncellenir. Tam taramada yalnızca taranan subnet içindeki eski kayıtlar offline işaretlenir; diğer ağ segmentlerindeki kayıtlar korunur. İlk görülme zamanı korunur, son görülme zamanı yeni keşifte güncellenir.

## Varsayılan test cihazı
- MAC: \`B8:AB:61:AB:DA:6E\`
- Etiket üzerindeki cihaz: Cisco Meraki MS120-24P
- Seri: \`Q4DE-57E5-WTP9\`

Vendor bilgisi OUI ön ekine dayalı tahmindir; MAC prefix tek başına cihazın kesin modelini veya seri numarasını kanıtlamaz.

## Meraki API
Meraki sayfasında API key yalnızca mevcut uygulama oturumunda bellekte kullanılır; SQLite'a veya kaynak koda yazılmaz. Erişilebilir organizasyonlarda switch port status kayıtları sorgulanır ve API'nin döndürdüğü \`clientMac\` alanı hedef MAC ile eşleştirilir. Meraki Dashboard API yetkisi ve cihazın port durumunda görünür client bilgisi gerekir.

## Ağ kapsamı ve sınırlamalar
- Tarama sadece seçilen aktif adaptörün yerel subnet'i içinde yapılır. Başka ağlara/uzak subnet'lere tarama reddedilir.
- Maksimum subnet boyutu 4.096 host ile sınırlandırılmıştır.
- MAC-IP eşleşmesi ARP ile aynı Layer-2/VLAN segmentinde yapılabilir. Farklı VLAN'larda Meraki/router/switch yönetim API'si gerekir.
- Ping yanıtı vermeyen ve ARP tablosunda görünmeyen cihaz keşfedilemeyebilir.
- Hostname çözümleme best-effort'tür; DNS/mDNS/NetBIOS yapılandırmasına bağlıdır.
- Switch port, VLAN veya PoE bilgisi Meraki API tarafından ilgili cihaz için döndürülmezse gösterilmez.
- Bu program port taraması, Wi-Fi saldırısı, deauthentication, packet injection, monitor mode veya exploit işlevi içermez.
- Gerçek ağ testi, Windows 10/11 bilgisayarında ve hedef yerel ağa bağlıyken yapılmalıdır.

## Tests
\`\`\`powershell
python -m compileall -q main.py mac_finder tests
python -m unittest discover -s tests -v
\`\`\`
