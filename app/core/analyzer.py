from typing import Dict, Any, List, Tuple
from dataclasses import dataclass

@dataclass
class Finding:
    category: str
    status: str
    risk: str
    details: str
    deduction: int
    hint: str

class RiskAnalyzer:
    def __init__(self, scan_results: Dict[str, Any]):
        self.data = scan_results
        self.score = 100
        self.findings: List[Finding] = []

    def analyze(self) -> Tuple[int, List[Finding]]:
        if self.data["status"] != "up":
            return 0, [Finding("Bağlantı", "FAIL", "CRITICAL", "Hedef yanıt vermiyor.", 100, "")]

        # --- 1. Hassas Dosyalar & SSL (CRITICAL: -25 Puan) ---
        
        # .env, .git vb.
        exposed_sens = self.data.get("exposed_sensitive", [])
        if exposed_sens:
            self.score -= 25
            self.findings.append(Finding(
                "Sensitive Files", "FAIL", "CRITICAL",
                f"Kritik dosyalar açık: {', '.join(exposed_sens)}",
                25, "Bunları hemen sunucudan silin veya erişime kapatın!"
            ))
        else:
            self.findings.append(Finding("Sensitive Files", "PASS", "SAFE", "Hassas dosyalar bulunamadı.", 0, ""))

        # SSL Durumu
        ssl_info = self.data.get("ssl_info", {})
        if not ssl_info.get("valid"):
            self.score -= 25
            self.findings.append(Finding(
                "SSL/TLS", "FAIL", "CRITICAL",
                f"Sertifika hatası: {ssl_info.get('error')}",
                25, "Geçerli bir SSL sertifikası (LetsEncrypt) kullanın."
            ))
        else:
            self.findings.append(Finding("SSL/TLS", "PASS", "SAFE", "Sertifika geçerli.", 0, ""))

        # --- 2. Admin & Docs & HTTPS (HIGH: -15 Puan) ---
        
        # Admin
        if self.data.get("exposed_admin"):
            self.score -= 15
            self.findings.append(Finding(
                "Admin Panel", "FAIL", "HIGH",
                f"Admin paneli bulundu: {self.data['exposed_admin'][0]}",
                15, "Admin panelini IP kısıtlamasına alın."
            ))
        
        # Swagger/Docs
        if self.data.get("exposed_docs"):
            self.score -= 15
            self.findings.append(Finding(
                "API Docs", "FAIL", "HIGH",
                "API Dökümantasyonu dışarı açık.",
                15, "Prod ortamında Swagger'ı devre dışı bırakın."
            ))

        # HTTPS Enforce
        if not self.data.get("https_enforced"):
            self.score -= 15
            self.findings.append(Finding(
                "HTTPS Redirect", "FAIL", "HIGH",
                "HTTP -> HTTPS yönlendirmesi yok.",
                15, "Tüm trafiği HTTPS'e zorlayın."
            ))

        # --- 3. Rate Limit & CORS (MEDIUM: -8 Puan) ---
        
        # Rate Limit
        if self.data.get("rate_limit") == "No-Throttle":
            self.score -= 8
            self.findings.append(Finding(
                "Rate Limiting", "WARN", "MEDIUM",
                "Arka arkaya isteklere 429 dönmedi.",
                8, "API Gateway üzerinde Rate Limit tanımlayın."
            ))
        
        # CORS
        if self.data.get("cors_wildcard"):
            self.score -= 8
            self.findings.append(Finding(
                "CORS Policy", "FAIL", "MEDIUM",
                "Wildcard (*) erişim izni var.",
                8, "Spesifik origin belirtin."
            ))

        # --- 4. Security Headers (LOW: -3 Puan) ---
        
        missing = self.data.get("missing_headers", [])
        if missing:
            deduction = min(len(missing) * 3, 15) # Max 15 puan keselim toplamda
            self.score -= deduction
            self.findings.append(Finding(
                "Security Headers", "WARN", "LOW",
                f"Eksik headerlar: {', '.join(missing[:3])}...",
                deduction, "HSTS, CSP ve X-Frame-Options ekleyin."
            ))
        else:
            self.findings.append(Finding("Security Headers", "PASS", "SAFE", "Tüm kritik headerlar mevcut.", 0, ""))

        # --- Info (Puan kırmaz) ---
        stack = self.data.get("tech_stack", "Unknown")
        self.findings.append(Finding("Tech Stack", "INFO", "INFO", f"Fingerprint: {stack}", 0, "Bilgi sızıntısını en aza indirin."))

        # Tehlikeli Metodlar
        methods = self.data.get("methods", [])
        unsafe = [m for m in methods if m in ["PUT", "DELETE", "PATCH"]]
        if unsafe:
            self.findings.append(Finding("HTTP Methods", "WARN", "MEDIUM", f"Tehlikeli metodlar açık: {unsafe}", 0, "Gereksiz HTTP verb'lerini kapatın."))

        self.score = max(0, self.score)
        return self.score, self.findings