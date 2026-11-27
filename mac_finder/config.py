"""Application configuration defaults."""
class Config:
    DEFAULT_TEST_MAC = "B8:AB:61:AB:DA:6E"
    DEFAULT_DEVICE = "Cisco Meraki MS120-24P"
    DEFAULT_SERIAL = "Q4DE-57E5-WTP9"

    @classmethod
    def get_test_mac(cls):
        return cls.DEFAULT_TEST_MAC

    @classmethod
    def get_test_device(cls):
        return cls.DEFAULT_DEVICE

    @classmethod
    def get_test_serial(cls):
        return cls.DEFAULT_SERIAL
