from core.interface import NetworkInterfaceManager
from core.db import Database

def test_interface_detection():
    info = NetworkInterfaceManager.get_primary_interface()
    assert "local_ip" in info
    assert "subnet_cidr" in info
    assert "iface_name" in info

def test_subnet_boundary_enforcement():
    assert NetworkInterfaceManager.is_in_local_subnet("192.168.1.50", "192.168.1.0/24") is True
    assert NetworkInterfaceManager.is_in_local_subnet("10.0.0.1", "192.168.1.0/24") is False

def test_database_device_and_alert_crud():
    Database.init_db()
    Database.save_blocked_ip_sync("192.168.1.250", reason="Test Ban")
    blocked = Database.get_all_blocked_ips_sync()
    ips = [b["ip"] for b in blocked]
    assert "192.168.1.250" in ips
    Database.remove_blocked_ip_sync("192.168.1.250")
    blocked_after = Database.get_all_blocked_ips_sync()
    ips_after = [b["ip"] for b in blocked_after]
    assert "192.168.1.250" not in ips_after

def test_out_of_bound_scan_rejection():
    assert NetworkInterfaceManager.is_in_local_subnet("8.8.8.8", "192.168.1.0/24") is False
