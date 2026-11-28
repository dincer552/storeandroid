"""Unit tests for Wi-Fi and endpoint security modules."""
import unittest
from mac_finder.network.wifi import (
    _security_classify, _security_severity, _quality_to_percentage,
    _channel_to_freq, _freq_to_band, _auth_name, _cipher_name, _phy_name,
    _signal_to_rssi, _band_from_phy,
)
from mac_finder.network.winevent import (
    LOGON_TYPES, LOGIN_EVENTS, WLAN_EVENT_TYPES, NPS_EVENTS,
    _parse_iso_time, _ID_FILTER,
)


class TestWifiSecurity(unittest.TestCase):
    def test_security_classify_open(self):
        self.assertEqual(_security_classify("Open", "None"), "Open")
        self.assertEqual(_security_classify("OPEN", ""), "Open")

    def test_security_classify_wep(self):
        self.assertEqual(_security_classify("WEP", "WEP104"), "WEP")

    def test_security_classify_wpa(self):
        self.assertEqual(_security_classify("WPA-PSK", "TKIP"), "WPA")

    def test_security_classify_wpa2(self):
        self.assertEqual(_security_classify("WPA2", "CCMP"), "WPA2")
        self.assertEqual(_security_classify("RSNA", "CCMP"), "WPA2")

    def test_security_classify_wpa3(self):
        self.assertEqual(_security_classify("WPA3", "CCMP"), "WPA3")
        self.assertEqual(_security_classify("WPA2/WPA3", "CCMP"), "WPA3")

    def test_security_severity(self):
        sev, msg = _security_severity("Open", "None")
        self.assertEqual(sev, "high")
        self.assertIn("Open", msg)
        sev, msg = _security_severity("WEP", "WEP104")
        self.assertEqual(sev, "high")
        sev, msg = _security_severity("WPA2", "CCMP")
        self.assertEqual(sev, "info")
        sev, msg = _security_severity("WPA3", "CCMP")
        self.assertEqual(sev, "info")


class TestWifiParsing(unittest.TestCase):
    def test_quality_to_percentage(self):
        self.assertEqual(_quality_to_percentage(150), 100)
        self.assertEqual(_quality_to_percentage(-10), 0)
        self.assertEqual(_quality_to_percentage(75), 75)

    def test_channel_to_freq(self):
        self.assertEqual(_channel_to_freq(1, "2.4"), 2412)
        self.assertEqual(_channel_to_freq(6, "2.4"), 2437)
        self.assertEqual(_channel_to_freq(36, "5"), 5180)
        self.assertEqual(_channel_to_freq(149, "5"), 5745)

    def test_freq_to_band(self):
        self.assertEqual(_freq_to_band(2437), "2.4")
        self.assertEqual(_freq_to_band(5180), "5")
        self.assertEqual(_freq_to_band(7150), "6")

    def test_auth_name(self):
        self.assertEqual(_auth_name(0), "Open")
        self.assertEqual(_auth_name(1), "Shared")
        self.assertEqual(_auth_name(2), "WPA-PSK")
        self.assertEqual(_auth_name(4), "WPA2")

    def test_cipher_name(self):
        self.assertEqual(_cipher_name(0), "None")
        self.assertEqual(_cipher_name(3), "CCMP")
        self.assertEqual(_cipher_name(5), "GCMP")

    def test_phy_name(self):
        self.assertEqual(_phy_name(7), "HT (Wi-Fi 4)")
        self.assertEqual(_phy_name(8), "VHT (Wi-Fi 5)")
        self.assertEqual(_phy_name(9), "HE (Wi-Fi 6)")

    def test_signal_to_rssi(self):
        self.assertEqual(_signal_to_rssi(100), -50)
        self.assertEqual(_signal_to_rssi(0), -100)
        self.assertEqual(_signal_to_rssi(50), -75)

    def test_band_from_phy(self):
        self.assertEqual(_band_from_phy(8, 5180), "5")
        self.assertEqual(_band_from_phy(9, 7150), "6")
        self.assertEqual(_band_from_phy(7, 2437), "2.4")


class TestWinevent(unittest.TestCase):
    def test_parse_iso_time(self):
        ts = _parse_iso_time("2024-01-01T12:34:56.789Z")
        self.assertIsInstance(ts, float)
        self.assertGreater(ts, 1700000000)
        # Invalid time returns 0
        self.assertEqual(_parse_iso_time("invalid"), 0.0)

    def test_id_filter(self):
        self.assertEqual(_ID_FILTER("1,2,3"), "EventID=1 or EventID=2 or EventID=3")

    def test_logon_types(self):
        self.assertEqual(LOGON_TYPES["2"], "Interactive")
        self.assertEqual(LOGON_TYPES["10"], "RemoteInteractive")

    def test_event_ids(self):
        self.assertEqual(LOGIN_EVENTS[4624], "Successful Logon")
        self.assertEqual(LOGIN_EVENTS[4625], "Failed Logon")
        self.assertEqual(WLAN_EVENT_TYPES[8001], "Connection")
        self.assertEqual(NPS_EVENTS[6272], "Access Granted")


class TestChannelMapping(unittest.TestCase):
    """Test Wi-Fi channel to frequency mapping."""

    def test_2ghz_channels(self):
        for ch in range(1, 14):
            freq = _channel_to_freq(ch, "2.4")
            self.assertGreaterEqual(freq, 2412)
            self.assertLessEqual(freq, 2484)

    def test_5ghz_channels(self):
        for ch in [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 149, 153, 157, 161, 165]:
            freq = _channel_to_freq(ch, "5")
            self.assertGreaterEqual(freq, 5180)
            self.assertLessEqual(freq, 5825)

    def test_6ghz_channels(self):
        for ch in [1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93]:
            freq = _channel_to_freq(ch, "6")
            self.assertGreaterEqual(freq, 5955)
            self.assertLessEqual(freq, 7115)


if __name__ == "__main__":
    unittest.main()