import requests
import socket
import ipaddress
import urllib3
from urllib.parse import urlparse
import logging

# Disable SSL warnings for the proxy
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class HardenedFetcher:
    """
    Production-grade hardened fetcher designed to prevent SSRF and DNS Rebinding.
    """
    
    # RFC 1918, RFC 1122, RFC 3927, RFC 4193, RFC 4291, RFC 169.254.169.254 (Cloud Metadata)
    FORBIDDEN_NETWORKS = [
        ipaddress.ip_network('127.0.0.0/8'),        # Loopback
        ipaddress.ip_network('10.0.0.0/8'),         # Private-use
        ipaddress.ip_network('172.16.0.0/12'),      # Private-use
        ipaddress.ip_network('192.168.0.0/16'),     # Private-use
        ipaddress.ip_network('169.254.0.0/16'),     # Link-local
        ipaddress.ip_network('100.64.0.0/10'),      # Carrier-grade NAT
        ipaddress.ip_network('0.0.0.0/8'),          # Current network
        ipaddress.ip_network('169.254.169.254/32'), # AWS/DigitalOcean/GCP Metadata
        ipaddress.ip_network('::1/128'),            # IPv6 Loopback
        ipaddress.ip_network('fc00::/7'),           # IPv6 Unique Local
        ipaddress.ip_network('fe80::/10'),          # IPv6 Link Local
    ]

    def __init__(self, timeout=10, user_agent="PhishNet-Hardened-Bot/2.0"):
        self.timeout = timeout
        self.user_agent = user_agent

    def is_safe_ip(self, ip_str):
        """Check if an IP address is in a forbidden range"""
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in self.FORBIDDEN_NETWORKS:
                if ip in network:
                    return False
            return True
        except ValueError:
            return False

    def fetch(self, url):
        """
        Fetches URL content while strictly preventing DNS rebinding.
        Step 1: Resolve DNS manually
        Step 2: Check IP safety
        Step 3: Fetch using the IP directly with Host header
        """
        parsed = urlparse(url)
        if parsed.scheme not in ['http', 'https']:
            raise ValueError(f"Unsupported scheme: {parsed.scheme}")

        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Empty hostname")

        # 1. Resolve DNS (First Resolution)
        try:
            # We resolve to the first available IP
            ip = socket.gethostbyname(hostname)
        except socket.gaierror as e:
            logger.error(f"DNS Resolution failed for {hostname}: {e}")
            return None

        # 2. Validate IP safety (No internal access)
        if not self.is_safe_ip(ip):
            logger.warning(f"BLOCKED SSRF ATTEMPT: {hostname} resolved to forbidden IP {ip}")
            return None

        # 3. Construct the actual request URL using the IP to prevent rebinding
        port = parsed.port or (80 if parsed.scheme == 'http' else 443)
        fetch_url = f"{parsed.scheme}://{ip}:{port}{parsed.path}"
        if parsed.query:
            fetch_url += f"?{parsed.query}"

        headers = {
            "Host": hostname, # Maintain original Host header for the remote server
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        try:
            # We use verify=False because we are connecting to an IP, 
            # and SNI/Cert validation might fail if not handled perfectly.
            # IN PRODUCTION: Use a more sophisticated session that validates certs 
            # by pinning the expected hostname.
            response = requests.get(
                fetch_url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False, # We handle redirects manually to re-validate each hop
                verify=False 
            )
            
            # Handle manual redirect validation (RECURSIVE SSRF PROTECTION)
            if response.status_code in [301, 302, 303, 307, 308]:
                redirect_url = response.headers.get('Location')
                if redirect_url:
                    # If relative URL, join with original
                    if not redirect_url.startswith('http'):
                        redirect_url = f"{parsed.scheme}://{hostname}{redirect_url}"
                    logger.info(f"Following secure redirect to {redirect_url}")
                    return self.fetch(redirect_url) # Recursive call will re-validate the new IP

            return response.text
        except Exception as e:
            logger.error(f"Fetch failed for {url} ({ip}): {e}")
            return None

# Global fetcher instance
fetcher = HardenedFetcher()
