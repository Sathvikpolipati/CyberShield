import pytest
from core.interface import NetworkInterfaceManager
from core.env_checker import EnvironmentChecker
from core.db import Database
from scanners.port_scanner import PortScanner

def test_interface_detection():
    info = NetworkInterfaceManager.get_primary_interface()
    assert "local_ip" in info
    assert "subnet_cidr" in info
    assert "/" in info["subnet_cidr"]

def test_subnet_boundary_enforcement():
    info = NetworkInterfaceManager.get_primary_interface()
    local_subnet = info["subnet_cidr"]
    local_ip = info["local_ip"]

    assert NetworkInterfaceManager.is_in_local_subnet(local_ip, local_subnet) is True
    assert NetworkInterfaceManager.is_in_local_subnet("8.8.8.8", local_subnet) is False
    assert NetworkInterfaceManager.is_in_local_subnet("1.1.1.1", local_subnet) is False
    assert NetworkInterfaceManager.is_in_local_subnet("172.217.16.206", local_subnet) is False

def test_database_device_and_alert_crud():
    Database.init_db()
    test_device = {
        "ip": "10.173.122.99",
        "hostname": "Test-Device",
        "mac": "00:11:22:33:44:55",
        "vendor": "Test Vendor",
        "status": "ONLINE",
        "latency_ms": 1.5,
        "open_ports": [80, 443]
    }
    Database.upsert_device_sync(test_device)
    
    test_alert = {
        "rule_name": "Test Port Scan",
        "severity": "HIGH",
        "attacker_ip": "10.173.122.99",
        "target_ip": "10.173.122.115",
        "description": "Port scan test event"
    }
    Database.save_alert_sync(test_alert)

def test_out_of_bound_scan_rejection():
    res = PortScanner.scan_target("8.8.8.8")
    assert "error" in res
    assert res["error"] == "OUT_OF_SCOPE"
