# MAC Finder Pro – Network Infrastructure Toolbox

Windows masaüstü uygulaması: yerel IPv4 keşfi, MAC-IP bulma, sınırlı TCP port kontrolü, Ethernet adaptör bilgileri, temel ağ tanılaması ve isteğe bağlı Cisco Meraki envanter erişimi.

## Özellikler
- Koyu temalı, navigasyon menülü masaüstü arayüzü
- Dashboard ve yerel komşu görünümü
- IP/CIDR taraması: ARP komşu tablosu + sınırlı eşzamanlı ping + tarama sonrası ARP yenileme
- MAC Finder: normalize edilmiş MAC arama ve IP eşleşmesi
- TCP port kontrolü: tek hedefte kullanıcı tarafından belirtilen en fazla 512 port
- Ethernet Analyzer: OS'den alınan IPv4, subnet, varsayılan gateway, link hızı, MTU, duplex ve trafik sayaçları
- Diagnostics: adaptör yapılandırması ve gateway ICMP erişim kontrolü
- Meraki Dashboard: API anahtarıyla kuruluş cihaz envanterini okuma (yalnızca oturum süresince)
- CSV dışa aktarma ve oturumluk tarama geçmişi

## Kurulum
\`\`\`powershell
python -m pip install -r requirements.txt
python main.py
\`\`\`

## Windows EXE
\`build.bat\` çalıştırın. Çıktı: \`dist\\MACFinder.exe\`.
GitHub Actions, Python modüllerini derler, aynı adlı EXE'yi oluşturur ve artifact olarak yükler. \`v*\` etiketi push edilirse ayrıca GitHub Release yayımlar.

## Sınırlamalar
- ARP yalnızca yerel L2/VLAN segmentinde MAC-IP eşleşmesini görebilir. Farklı VLAN'lar için router/switch/controller verisi gerekir.
- Network Map mantıksal komşu görünümüdür; fiziksel port bağlantısını iddia etmez.
- Bu sürüm Meraki kuruluş cihaz envanterini okur; switch-port, VLAN veya PoE eşlemesini henüz tamamlamaz.
- Link speed, duplex ve MTU işletim sisteminin adaptör raporudur; kablo sınıfı, uzak switch portu ve PoE bilgisi değildir.
- TCP port kontrolü yalnızca seçilen tek hedef ve portlar için çalışır. Yalnızca yetkili olduğunuz ağlarda kullanın.
- Büyük subnetler kaynak tüketimini sınırlamak için 4.096 adresle sınırlandırılmıştır.
- Ping yanıtı vermeyen ve ARP tablosuna eklenmeyen cihazın MAC adresi keşfedilemeyebilir.
- Gerçek Windows ağ davranışı Windows makinede ve hedef ağa erişimle doğrulanmalıdır.

## Test MAC
\`B8:AB:61:AB:DA:6E\` (etiketteki örnek Meraki MS120-24P MAC adresi).
