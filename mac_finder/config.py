import os
from pathlib import Path

class Config:
    """Configuration class for MAC Finder."""
    
    # Default Meraki API key (empty means disabled)
    MERAKI_API_KEY = ""
    
    # Default test MAC address
    DEFAULT_TEST_MAC = "B8:AB:61:AB:DA:6E"
    
    # Default test device
    DEFAULT_DEVICE = "Cisco Meraki MS120-24P"
    
    # Default test serial number
    DEFAULT_SERIAL = "Q4DE-57E5-WTP9"
    
    @classmethod
    def get_test_mac(cls):
        """Get default test MAC address."""
        return cls.DEFAULT_TEST_MAC
    
    @classmethod
    def get_test_device(cls):
        """Get default test device name."""
        return cls.DEFAULT_DEVICE
    
    @classmethod
    def get_test_serial(cls):
        """Get default test serial number."""
        return cls.DEFAULT_SERIAL