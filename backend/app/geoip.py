import os
import geoip2.database
import geoip2.errors
from typing import Dict, Any, Optional
import functools
from app.db_manager import ensure_databases

class GeoIPService:
    """
    Enriches public IP addresses with latitude, longitude, country, city, ASN, and ISP.
    Uses offline DB-IP / MaxMind databases for zero-latency, rate-limit-free lookups.
    """
    def __init__(self):
        # Automatically download offline databases if missing
        ensure_databases()
        
        temp_dir = os.path.join(os.getcwd(), "temp", "mmdb")
        self.city_db_path = os.path.join(temp_dir, "dbip-city-lite.mmdb")
        self.asn_db_path = os.path.join(temp_dir, "dbip-asn-lite.mmdb")
        
        self.city_reader = None
        self.asn_reader = None
        
        try:
            if os.path.exists(self.city_db_path):
                self.city_reader = geoip2.database.Reader(self.city_db_path)
            if os.path.exists(self.asn_db_path):
                self.asn_reader = geoip2.database.Reader(self.asn_db_path)
        except Exception as e:
            print(f"[GeoIPService] Failed to initialize geoip2 readers: {e}")

    def is_private_ip(self, ip: str) -> bool:
        if not ip or ip == 'N/A' or ip == 'Unknown':
            return True
        # Localhost/Loopback
        if ip.startswith("127.") or ip == "::1" or ip == "localhost":
            return True
        # Private classes
        if ip.startswith("192.168.") or ip.startswith("10."):
            return True
        if ip.startswith("172."):
            try:
                parts = ip.split('.')
                if len(parts) >= 2:
                    second = int(parts[1])
                    return 16 <= second <= 31
            except ValueError:
                pass
        # APIPA link-local
        if ip.startswith("169.254."):
            return True
        # Broadcast/Multicast
        if ip.startswith("224.") or ip.startswith("255.255.") or ip == "0.0.0.0":
            return True
        return False

    @functools.lru_cache(maxsize=10000)
    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Returns geo info for an IP synchronously using offline databases.
        """
        if self.is_private_ip(ip):
            return {
                "country": "Local Network",
                "code": "LO",
                "city": "Private Subnet",
                "lat": 0.0,
                "lon": 0.0,
                "isp": "Local",
                "asn": "Private"
            }
            
        country = "Unknown"
        code = "??"
        city = "Unknown"
        lat = None
        lon = None
        isp = "Unknown"
        asn = "Unknown"
        
        try:
            if self.city_reader:
                city_response = self.city_reader.city(ip)
                if city_response.country.name:
                    country = city_response.country.name
                if city_response.country.iso_code:
                    code = city_response.country.iso_code
                if city_response.city.name:
                    city = city_response.city.name
                if city_response.location.latitude is not None:
                    lat = float(city_response.location.latitude)
                if city_response.location.longitude is not None:
                    lon = float(city_response.location.longitude)
        except geoip2.errors.AddressNotFoundError:
            pass
        except Exception as e:
            print(f"[GeoIPService] City lookup error for {ip}: {e}")
            
        try:
            if self.asn_reader:
                asn_response = self.asn_reader.asn(ip)
                if asn_response.autonomous_system_organization:
                    isp = asn_response.autonomous_system_organization
                if asn_response.autonomous_system_number:
                    asn = f"AS{asn_response.autonomous_system_number}"
        except geoip2.errors.AddressNotFoundError:
            pass
        except Exception as e:
            print(f"[GeoIPService] ASN lookup error for {ip}: {e}")

        return {
            "country": country,
            "code": code,
            "city": city,
            "lat": lat,
            "lon": lon,
            "isp": isp,
            "asn": asn
        }

# Global geoip resolver instance
geoip_resolver = GeoIPService()
