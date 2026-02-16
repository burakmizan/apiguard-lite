import httpx
import asyncio
import ssl
import socket
from urllib.parse import urlparse
from typing import Dict, Any, List
from datetime import datetime


from app.core.payloads import DOCS_PATHS, ADMIN_PATHS


SENSITIVE_FILES = [
    "/.env",
    "/.git/config",
    "/config.json",
    "/config.php",
    "/backup.sql",
    "/.htaccess",
    "/.DS_Store",
    "/server-status"
]


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

class APIScanner:
    def __init__(self, target: str):
        self.target = target
        self.domain = urlparse(target).netloc
        self.results = {
            "exposed_docs": [],
            "exposed_admin": [],
            "exposed_sensitive": [],
            "missing_headers": [],
            "headers": {},
            "methods": [],
            "ssl_info": None,
            "rate_limit": None,
            "tech_stack": "Unknown",
            "https_enforced": False,
            "cors_wildcard": False,
            "status": "pending"
        }
        self.headers = {"User-Agent": "APIGuard-Lite/2.0 (Defensive-Audit)"}

    async def _check_path(self, client: httpx.AsyncClient, path: str) -> str | None:

        try:
            response = await client.get(path, follow_redirects=True)

            if response.status_code == 200 and len(response.content) > 50: 
                return path
        except:
            pass
        return None

    async def _check_ssl(self):

        def get_cert_info():
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((self.domain, 443), timeout=3.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        cert = ssock.getpeercert()
                        return {
                            "valid": True,
                            "issuer": dict(x[0] for x in cert['issuer']),
                            "expires": cert['notAfter']
                        }
            except ssl.SSLCertVerificationError:
                return {"valid": False, "error": "Self-Signed or Invalid Chain"}
            except Exception as e:
                return {"valid": False, "error": str(e)}

        return await asyncio.to_thread(get_cert_info)

    async def _check_rate_limit(self, client: httpx.AsyncClient):

        responses = []
        for _ in range(5):
            try:
                resp = await client.get(self.target)
                responses.append(resp.status_code)
            except:
                pass
        
        if 429 in responses:
            return "Protected"
        elif all(r == 200 for r in responses):
            return "No-Throttle" # Kötü haber
        else:
            return "Unknown"

    async def scan(self) -> Dict[str, Any]:
        try:
            # verify=False yapıyoruz ki self-signed dev ortamlarını da tarayabilelim.
            async with httpx.AsyncClient(timeout=8.0, verify=False, headers=self.headers) as client:
                # 1. Ana İstek & Header Analizi
                root_resp = await client.get(self.target)
                self.results["headers"] = dict(root_resp.headers)
                self.results["status"] = "up"
                
                # Tech Stack Fingerprinting (Basit versiyon)
                server_h = root_resp.headers.get("Server", "")
                powered_h = root_resp.headers.get("X-Powered-By", "")
                self.results["tech_stack"] = f"{server_h} {powered_h}".strip() or "Hidden"

                # Security Headers Check
                for h in SECURITY_HEADERS:
                    if h not in root_resp.headers: # Case-insensitive aslında httpx ile halledilir ama basit tutalım
                        # httpx headers case-insensitive'dir, direkt bakabiliriz.
                        if h not in root_resp.headers:
                            self.results["missing_headers"].append(h)

                # CORS Check
                if root_resp.headers.get("access-control-allow-origin") == "*":
                    self.results["cors_wildcard"] = True

                # HTTP Methods Check (OPTIONS)
                try:
                    opt_resp = await client.options(self.target)
                    allow_header = opt_resp.headers.get("Allow", "")
                    self.results["methods"] = [m.strip() for m in allow_header.split(",") if m]
                except:
                    pass

                # Rate Limit Test
                self.results["rate_limit"] = await self._check_rate_limit(client)

                # 2. Path Enumeration (Gather ile paralel saldırı)
                tasks = []
                # Docs
                tasks.extend([self._check_path(client, self.target + p) for p in DOCS_PATHS])
                # Admin
                tasks.extend([self._check_path(client, self.target + p) for p in ADMIN_PATHS])
                # Sensitive Files (.env vs)
                tasks.extend([self._check_path(client, self.target + p) for p in SENSITIVE_FILES])

                all_paths = await asyncio.gather(*tasks)

                # Sonuçları ayrıştır
                idx_docs = len(DOCS_PATHS)
                idx_admin = idx_docs + len(ADMIN_PATHS)
                
                self.results["exposed_docs"] = [p for p in all_paths[:idx_docs] if p]
                self.results["exposed_admin"] = [p for p in all_paths[idx_docs:idx_admin] if p]
                self.results["exposed_sensitive"] = [p for p in all_paths[idx_admin:] if p]

        except (httpx.ConnectError, httpx.TimeoutException):
            self.results["status"] = "down"
            return self.results
        except Exception as e:
            self.results["status"] = "error"
            self.results["error_msg"] = str(e)
            return self.results

        # 3. SSL Check & HTTPS Enforce (Ayrı mantıklar)
        self.results["ssl_info"] = await self._check_ssl()
        
        # HTTPS Enforce kontrolü
        try:
            if self.target.startswith("https://"):
                http_target = self.target.replace("https://", "http://")
                async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
                    resp = await client.get(http_target)
                    if 300 <= resp.status_code < 400 and resp.headers.get("location", "").startswith("https://"):
                        self.results["https_enforced"] = True
        except:
            pass

        return self.results