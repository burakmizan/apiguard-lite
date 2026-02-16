# app/utils/formatters.py
from urllib.parse import urlparse

def normalize_url(url: str) -> str:

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    
    parsed = urlparse(url)
    
    return f"{parsed.scheme}://{parsed.netloc}"