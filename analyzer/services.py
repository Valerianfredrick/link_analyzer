# Auto-generated formatting comment
import re
import ssl
import socket
import requests
import ipaddress
import urllib.parse
import math
from datetime import datetime, timezone
from typing import Optional
# Additional formatting comment

# ── Optional dependencies (graceful fallback if not installed) ──────────────
try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# ── Threat Dictionaries and Key Lists ───────────────────────────────────────
PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "banking", "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "instagram", "netflix", "password", "credential", "wallet", "crypto",
    "support", "helpdesk", "alert", "suspended", "unusual", "activity",
    "billing", "invoice", "refund", "signin", "login-page", "free-cash",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Free TLDs
    ".xyz", ".top", ".club", ".online",
    ".site", ".website", ".space", ".fun",
    ".buzz", ".click", ".link", ".live",
    ".work", ".cc", ".icu", ".fit", ".gdn"
}

BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "netflix": "netflix.com",
    "twitter": "twitter.com",
    "x": "x.com",
}

POPULAR_DOMAINS = [
    "google.com", "facebook.com", "apple.com", "microsoft.com", "amazon.com",
    "netflix.com", "paypal.com", "twitter.com", "x.com", "linkedin.com",
    "instagram.com", "youtube.com", "yahoo.com", "wikipedia.org", "live.com",
    "github.com", "reddit.com", "pinterest.com", "zoom.us", "dropbox.com",
    "ebay.com", "adobe.com", "spotify.com", "whatsapp.com", "tiktok.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "discord.com", "steamcommunity.com", "twitch.tv", "salesforce.com", "slack.com",
    "office.com"
]

SUSPICIOUS_IP_RANGES = [
    "185.220.",   # Tor exit nodes
    "194.165.",   # Known bulletproof hosting
    "45.142.",    # Common malware hosting
]

EXPLOIT_PATTERNS = {
    "SQL Injection": re.compile(r"('\s*(or|and)\s*\d+\s*=\s*\d+)|(union\s+select)|(--)|(/\*)", re.I),
    "Cross-Site Scripting (XSS)": re.compile(r"(<script)|(javascript:)|(onerror\s*=)|(onload\s*=)|(eval\()", re.I),
    "Directory Traversal": re.compile(r"(\.\./)|(\.\.\\)", re.I)
}

SOCIAL_ENGINEERING_PHRASES = [
    "verify your account", "confirm your identity", "suspend your card",
    "unauthorized login", "security alert", "update payment method",
    "billing error", "action required", "urgent update", "login again"
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "su.pr"
}


# ── Heuristic Helpers ────────────────────────────────────────────────────────

def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    probabilities = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probabilities)


def _get_domain_parts(domain: str) -> tuple[str, str]:
    """Split domain into Second Level Domain (SLD) and Top Level Domain (TLD)."""
    parts = domain.split('.')
    if len(parts) < 2:
        return domain, ""
    
    double_tlds = {"co", "com", "net", "org", "edu", "gov", "ac", "mil", "ltd"}
    if len(parts) >= 3 and parts[-2] in double_tlds:
        sld = parts[-3]
        tld = ".".join(parts[-2:])
    else:
        sld = parts[-2]
        tld = parts[-1]
    return sld, tld


def _extract_domain(url: str) -> tuple[str, str]:
    """Return (full_url_with_scheme, bare_domain)."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower().lstrip("www.")
    if ":" in domain:
        domain = domain.split(":")[0]
    return url, domain


# ── Inspection Routines ──────────────────────────────────────────────────────

def _check_ssl_advanced(hostname: str) -> dict:
    """Verify SSL certificate validity, issuer, expiry, and connection cipher metrics."""
    result = {
        "has_ssl": False,
        "valid_cert": False,
        "expired": False,
        "days_until_expiry": None,
        "issuer": "Unknown",
        "issuer_organization": "Unknown",
        "subject_cn": "Unknown",
        "protocol": "Unknown",
        "cipher": "Unknown",
        "issue": None,
    }
    try:
        ctx = ssl.create_default_context()
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        
        with socket.create_connection((hostname, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["has_ssl"] = True
                result["valid_cert"] = True
                result["protocol"] = ssock.version()
                cipher_info = ssock.cipher()
                if cipher_info:
                    result["cipher"] = cipher_info[0]

                # Parse expiry
                expire_str = cert.get("notAfter", "")
                if expire_str:
                    expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                    expire_dt = expire_dt.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    delta = (expire_dt - now).days
                    result["days_until_expiry"] = delta
                    result["expired"] = delta < 0

                # Parse issuer & subject
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer_dict.get("commonName", "Unknown")
                result["issuer_organization"] = issuer_dict.get("organizationName", "Unknown")
                
                subject_dict = dict(x[0] for x in cert.get("subject", []))
                result["subject_cn"] = subject_dict.get("commonName", "Unknown")

    except ssl.SSLCertVerificationError as e:
        result["has_ssl"] = True
        result["valid_cert"] = False
        result["issue"] = f"SSL Verification Error: {e.verify_message}"
        
        # Fallback to load basic certificate metadata unverified
        try:
            unverified_ctx = ssl._create_unverified_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with unverified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        expire_str = cert.get("notAfter", "")
                        if expire_str:
                            expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                            expire_dt = expire_dt.replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            delta = (expire_dt - now).days
                            result["days_until_expiry"] = delta
                            result["expired"] = delta < 0
                        
                        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                        result["issuer"] = issuer_dict.get("commonName", "Unknown")
                        result["issuer_organization"] = issuer_dict.get("organizationName", "Unknown")
                        
                        subject_dict = dict(x[0] for x in cert.get("subject", []))
                        result["subject_cn"] = subject_dict.get("commonName", "Unknown")
        except Exception:
            pass
    except ssl.SSLError as e:
        result["issue"] = f"SSL Protocol Error: {e}"
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        result["issue"] = f"Network Connection Failed: {e}"

    return result


def _check_security_headers(headers: dict) -> dict:
    """Analyze HTTP response headers for missing/loose security policy parameters."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    checks = {
        "csp": "content-security-policy" in headers_lower,
        "hsts": "strict-transport-security" in headers_lower,
        "x_frame": "x-frame-options" in headers_lower,
        "x_content_type": "x-content-type-options" in headers_lower,
        "referrer_policy": "referrer-policy" in headers_lower
    }
    
    score = 0
    if checks["csp"]: score += 25
    if checks["hsts"]: score += 25
    if checks["x_frame"]: score += 20
    if checks["x_content_type"]: score += 15
    if checks["referrer_policy"]: score += 15
    
    return {
        "headers_found": checks,
        "score": score,
        "csp_value": headers_lower.get("content-security-policy"),
        "hsts_value": headers_lower.get("strict-transport-security"),
        "x_frame_value": headers_lower.get("x-frame-options"),
        "x_content_type_value": headers_lower.get("x-content-type-options"),
        "referrer_policy_value": headers_lower.get("referrer-policy")
    }


def _scan_html_content(url: str, html_text: str, domain: str) -> dict:
    """Perform structural forensics on page HTML code to spot phishing indicators."""
    findings = []
    
    has_password_field = False
    has_cross_domain_form = False
    has_suspicious_scripts = False
    
    # 1. Login & Insecure Credentials form checks
    if re.search(r'<input\s+[^>]*type=["\']password["\']', html_text, re.I):
        has_password_field = True
        
        forms = re.findall(r'<form\s+[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', html_text, re.I | re.DOTALL)
        for action, form_body in forms:
            if 'type="password"' in form_body.lower() or "type='password'" in form_body.lower():
                if action.startswith("http://"):
                    findings.append("Vulnerable Password Form: Transmits user credentials over unencrypted HTTP")
                elif action.startswith(("https://", "//")):
                    action_full = action if action.startswith("https:") else "https:" + action
                    parsed_action = urllib.parse.urlparse(action_full)
                    action_domain = parsed_action.netloc.lower().lstrip("www.")
                    if action_domain and action_domain != domain:
                        has_cross_domain_form = True
                        findings.append(f"Dangerous Cross-Domain Submit: Form passes sensitive password data to '{action_domain}'")
        
        if not url.startswith("https://"):
            findings.append("Critical Security Warning: Password entry form hosted on non-HTTPS link")
        else:
            is_trusted = False
            for brand, bdomain in BRAND_DOMAINS.items():
                if domain == bdomain or domain.endswith("." + bdomain):
                    is_trusted = True
                    break
            if not is_trusted:
                findings.append("Login Warn: Input credentials field detected on unverified domain context")

    # 2. Obfuscated scripting patterns
    suspicious_keywords = ["eval(function(", "unescape(", "String.fromCharCode(", "window.atob(", "window.btoa("]
    for kw in suspicious_keywords:
        if kw in html_text:
            has_suspicious_scripts = True
            findings.append(f"Code Obfuscation: Script block features '{kw}' typical of malware evasions")
            break

    # 3. Hidden structures and hidden links
    hidden_tags = re.findall(r'<(iframe|div|a)\s+[^>]*(style=["\'][^"\']*(display:\s*none|visibility:\s*hidden|opacity:\s*0|left:\s*-\d+px|width:\s*0px|height:\s*0px)[^"\']*)', html_text, re.I)
    if hidden_tags:
        findings.append(f"Evasion Attempt: Detected {len(hidden_tags)} hidden iframes or overlays")

    # 4. Page title brand impersonation
    title_match = re.search(r'<title>([^<]+)</title>', html_text, re.I)
    if title_match:
        title = title_match.group(1).lower()
        for brand, bdomain in BRAND_DOMAINS.items():
            if brand in title and not (domain == bdomain or domain.endswith("." + bdomain)):
                findings.append(f"Brand Impersonation: Page title references '{brand.capitalize()}' but is hosted on '{domain}'")
                break

    # 5. Social engineering text phrases
    se_keywords_found = [p for p in SOCIAL_ENGINEERING_PHRASES if p in html_text.lower()]
    if len(se_keywords_found) >= 2:
        findings.append(f"Social Engineering: Content leverages coercive warning words: '{', '.join(se_keywords_found[:3])}'")

    # 6. Evasion blocker controls
    evasion_patterns = ["contextmenu", "preventDefault()", "event.button", "event.keyCode"]
    matches = sum(1 for ep in evasion_patterns if ep in html_text)
    if matches >= 3:
        findings.append("User Evasion: Page code restricts inspection tools or blocks right-clicks")

    # 7. Asset cloning indicator (Resource dominance ratio)
    all_refs = re.findall(r'(src|href)=["\'](https?://[^"\']+)["\']', html_text, re.I)
    external_refs = 0
    brand_refs = 0
    mapped_brands = set()
    
    for _, ref_url in all_refs:
        parsed_ref = urllib.parse.urlparse(ref_url)
        ref_domain = parsed_ref.netloc.lower().lstrip("www.")
        if ref_domain and ref_domain != domain:
            external_refs += 1
            for brand, bdomain in BRAND_DOMAINS.items():
                if ref_domain == bdomain or ref_domain.endswith("." + bdomain):
                    brand_refs += 1
                    mapped_brands.add(brand)
                    
    cloning_ratio = 0.0
    if external_refs > 5:
        cloning_ratio = brand_refs / external_refs
        if cloning_ratio > 0.65:
            brands_str = ", ".join(m.capitalize() for m in mapped_brands)
            findings.append(f"Phishing Clone Match: Loads {cloning_ratio * 100:.1f}% of resources from trusted '{brands_str}' servers")

    return {
        "findings": findings,
        "metrics": {
            "cloning_ratio": round(cloning_ratio, 2),
            "external_assets_count": external_refs,
            "brand_assets_count": brand_refs,
            "social_engineering_count": len(se_keywords_found),
            "evasion_scripts_count": matches
        }
    }


def _check_reachability(url: str) -> dict:
    """Check if the URL resolves, follows redirects step-by-step, and executes HTML forensic rules."""
    result = {
        "reachable": False,
        "status_code": None,
        "redirects": [],
        "redirect_chain": [],
        "final_url": url,
        "response_time_ms": None,
        "has_shortener": False,
        "cross_domain_redirect": False,
        "html_findings": [],
        "page_metrics": {},
        "security_headers": {},
        "issue": None
    }
    try:
        start = datetime.now()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 (LinkGuard Safety Scanner)"
        }
        resp = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers=headers,
            stream=True,
        )
        elapsed = (datetime.now() - start).total_seconds() * 1000
        result["reachable"] = True
        result["status_code"] = resp.status_code
        result["final_url"] = resp.url
        result["response_time_ms"] = round(elapsed)
        result["redirects"] = [r.url for r in resp.history]

        # Analyze full redirect chain
        chain = []
        start_domain = urllib.parse.urlparse(url).netloc.lower().lstrip("www.")
        last_domain = start_domain
        
        for r in resp.history:
            parsed_r = urllib.parse.urlparse(r.url)
            r_domain = parsed_r.netloc.lower().lstrip("www.")
            if r_domain in URL_SHORTENERS:
                result["has_shortener"] = True
            if r_domain and r_domain != last_domain:
                result["cross_domain_redirect"] = True
            last_domain = r_domain
            chain.append({
                "url": r.url,
                "status_code": r.status_code,
                "domain": r_domain
            })
            
        final_parsed = urllib.parse.urlparse(resp.url)
        final_domain = final_parsed.netloc.lower().lstrip("www.")
        if final_domain in URL_SHORTENERS:
            result["has_shortener"] = True
        if final_domain and final_domain != last_domain:
            result["cross_domain_redirect"] = True
            
        chain.append({
            "url": resp.url,
            "status_code": resp.status_code,
            "domain": final_domain
        })
        result["redirect_chain"] = chain

        # Read security headers
        result["security_headers"] = _check_security_headers(resp.headers)

        # Stream read first 80KB of page body
        content_bytes = b""
        for chunk in resp.iter_content(chunk_size=1024):
            content_bytes += chunk
            if len(content_bytes) >= 81920:
                break
        
        html_text = content_bytes.decode('utf-8', errors='ignore')
        
        result["page_metrics"] = {
            "size_kb": round(len(content_bytes) / 1024, 2),
            "scripts_count": len(re.findall(r'<script', html_text, re.I)),
            "forms_count": len(re.findall(r'<form', html_text, re.I)),
            "iframes_count": len(re.findall(r'<iframe', html_text, re.I))
        }

        # Analyze HTML content
        scan_res = _scan_html_content(resp.url, html_text, final_domain)
        result["html_findings"] = scan_res["findings"]
        result["html_metrics"] = scan_res["metrics"]

    except requests.exceptions.SSLError:
        result["reachable"] = False
        result["issue"] = "SSL Certificate Verification Failed"
    except requests.exceptions.ConnectionError:
        result["reachable"] = False
        result["issue"] = "Host Connection Refused"
    except requests.exceptions.Timeout:
        result["reachable"] = False
        result["issue"] = "Connection Timeout"
    except Exception as e:
        result["reachable"] = False
        result["issue"] = str(e)
    return result


def _check_domain_age(domain: str) -> dict:
    """Look up WHOIS register data to establish domain age."""
    result = {
        "domain_age_days": None,
        "registered_on": None,
        "registrar": None,
        "issue": None,
    }
    if not WHOIS_AVAILABLE:
        result["issue"] = "whois not installed"
        return result
    try:
        w = whois_lib.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            result["domain_age_days"] = (now - created).days
            result["registered_on"] = created.strftime("%Y-%m-%d")
        result["registrar"] = w.registrar
    except Exception as e:
        result["issue"] = str(e)
    return result


def _check_ip(domain: str) -> dict:
    """Resolve domain hostname and verify routing subnets."""
    result = {
        "ip_address": None,
        "is_private": False,
        "is_suspicious_range": False,
        "issue": None,
    }
    try:
        ip = socket.gethostbyname(domain)
        result["ip_address"] = ip
        try:
            result["is_private"] = ipaddress.ip_address(ip).is_private
        except ValueError:
            pass
        result["is_suspicious_range"] = any(
            ip.startswith(r) for r in SUSPICIOUS_IP_RANGES
        )
    except socket.gaierror as e:
        result["issue"] = str(e)
    return result


def _check_dns_advanced(domain: str) -> dict:
    """Verify MX, SPF, DMARC, and DNSSEC signatures on domain registry."""
    result = {
        "has_mx": False,
        "has_spf": False,
        "spf_policy": "None",
        "spf_is_permissive": False,
        "has_dmarc": False,
        "dmarc_policy": "None",
        "has_dnssec": False,
        "issue": None
    }
    if not DNS_AVAILABLE:
        result["issue"] = "dnspython not installed"
        return result
    
    # 1. MX verification
    try:
        dns.resolver.resolve(domain, "MX")
        result["has_mx"] = True
    except Exception:
        pass
        
    # 2. SPF evaluation
    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
        for r in txt_records:
            txt_str = r.to_text().strip('"')
            if txt_str.startswith("v=spf1"):
                result["has_spf"] = True
                result["spf_policy"] = txt_str
                if "+all" in txt_str or (txt_str.endswith("all") and not ("-all" in txt_str or "~all" in txt_str)):
                    result["spf_is_permissive"] = True
                break
    except Exception:
        pass
        
    # 3. DMARC check
    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in dmarc_records:
            txt_str = r.to_text().strip('"')
            if "v=DMARC1" in txt_str:
                result["has_dmarc"] = True
                match = re.search(r"p=(none|quarantine|reject)", txt_str, re.I)
                if match:
                    result["dmarc_policy"] = match.group(1).lower()
                break
    except Exception:
        pass
        
    # 4. DNSSEC validation
    try:
        dns.resolver.resolve(domain, "DNSKEY")
        result["has_dnssec"] = True
    except Exception:
        pass
        
    return result


def _check_phishing_signals(url: str, domain: str) -> dict:
    """Heuristic scanner tracking typosquatting, character encoding, and high-risk geometries."""
    flags = []
    typosquatting_detected = False
    exploit_detected = False

    sld, tld_part = _get_domain_parts(domain)
    sld_entropy = _calculate_entropy(sld)

    # 1. Domain entropy check
    if len(sld) >= 10 and sld_entropy > 3.6:
        flags.append(f"Domain Entropy: Character entropy is {sld_entropy:.2f} (indicates machine-generated DGA domain)")

    # 2. Typosquatting distance check
    for pop_domain in POPULAR_DOMAINS:
        pop_sld, _ = _get_domain_parts(pop_domain)
        if domain == pop_domain or domain.endswith("." + pop_domain):
            continue
        dist = _levenshtein_distance(sld, pop_sld)
        if dist in [1, 2]:
            typosquatting_detected = True
            flags.append(f"Typosquatting Risk: Lookalike domain matching trusted brand '{pop_sld.capitalize()}' (distance {dist})")
            break

    # 3. Suspicious TLD
    tld_full = "." + tld_part
    if tld_full in SUSPICIOUS_TLDS:
        flags.append(f"High-Risk Registry: Uses registry TLD '{tld_full}' associated with free registration / scams")

    # 4. Brand impersonation
    for brand, real_domain in BRAND_DOMAINS.items():
        if brand in domain and not (domain == real_domain or domain.endswith("." + real_domain)):
            flags.append(f"Brand Impersonation: Domain matches name '{brand.capitalize()}' but is not official '{real_domain}'")

    # 5. Phishing keywords in domain
    found_kw = [kw for kw in PHISHING_KEYWORDS if kw in sld]
    if found_kw:
        flags.append(f"Phishing Keywords: Domain path uses keywords: {', '.join(found_kw[:3])}")

    # 6. Excessive subdomains
    parts = domain.split(".")
    if len(parts) > 4:
        flags.append(f"Excessive Subdomains: Found {len(parts) - 1} subdomain levels mapping (commonly hides true host)")

    # 7. Raw IP Address in URL
    try:
        ipaddress.ip_address(domain)
        flags.append("Obfuscation: URL uses raw IP address instead of registered domain hostname")
    except ValueError:
        pass

    # 8. Excessive length
    if len(url) > 100:
        flags.append(f"Suspicious Geometry: Unusually long URL ({len(url)} characters) standard in encoding obfuscation")

    # 9. Hex/percent encoding abuse
    if url.count("%") > 5:
        flags.append("Encoding Trick: Heavy percent encoding used (could obscure query payload signatures)")

    # 10. Non-ASCII Homographs
    try:
        domain.encode("ascii")
    except UnicodeEncodeError:
        flags.append("IDN Homograph Attack: Hostname contains internationalized Cyrillic/Greek characters resembling trusted names")

    # 11. High-risk downloads
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lower()
    high_risk_exts = {".exe", ".msi", ".scr", ".iso", ".zip", ".dmg", ".apk", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".pif", ".wsf"}
    for ext in high_risk_exts:
        if path.endswith(ext):
            flags.append(f"Malicious Executable Link: URL points directly to executable file format '{ext}'")
            break

    # 12. Exploit payloads in parameters
    query = parsed.query.lower()
    for name, pattern in EXPLOIT_PATTERNS.items():
        if pattern.search(query) or pattern.search(path):
            exploit_detected = True
            flags.append(f"Exploit Payload: Detectable '{name}' signature match found in query path")

    return {
        "flags": flags,
        "count": len(flags),
        "sld_entropy": round(sld_entropy, 2),
        "typosquatting_detected": typosquatting_detected,
        "exploit_detected": exploit_detected
    }


def _score_and_verdict(checks: dict) -> dict:
    """Calculate the final aggregated risk score (0-100) and security verdict."""
    score = 0
    reasons = []

    ssl_c = checks["ssl"]
    reach = checks["reachability"]
    domain_c = checks["domain_age"]
    ip_c = checks["ip"]
    phish = checks["phishing"]
    dns_c = checks["dns"]

    # 1. SSL Security
    if not ssl_c.get("has_ssl"):
        score += 25
        reasons.append("No HTTPS: Connection is unencrypted and vulnerable to traffic spoofing")
    elif not ssl_c.get("valid_cert"):
        score += 30
        reasons.append(f"Untrusted SSL: Certificate validation failed ({ssl_c.get('issue') or 'unverified CN'})")
    elif ssl_c.get("expired"):
        score += 20
        reasons.append("Expired SSL: Cryptographic security signature has expired")
    
    # 2. Reachability & Redirect Hops
    if not reach.get("reachable"):
        score += 20
        reasons.append(f"Server Unreachable: Connection handshake failed ({reach.get('issue', 'offline')})")
    
    redirects_count = len(reach.get("redirects", []))
    if redirects_count > 3:
        score += 15
        reasons.append(f"Evasion Redirects: Long redirect chain ({redirects_count} hops) designed to obfuscate target landing")
    if reach.get("has_shortener"):
        score += 10
        reasons.append("URL Shortener: Target masking using a popular shortening alias")
    if reach.get("cross_domain_redirect"):
        score += 15
        reasons.append("Multi-Domain Redirect Cascade: Redirections bounce through multiple distinct domains")

    # 3. Domain Age
    age = domain_c.get("domain_age_days")
    if age is not None:
        if age < 30:
            score += 35
            reasons.append(f"Newly Registered Domain: Created only {age} days ago (classic signature of disposable phishing sites)")
        elif age < 180:
            score += 15
            reasons.append(f"Young Registry Age: Domain is registered only {age} days ago")

    # 4. IP reputation
    if ip_c.get("is_suspicious_range"):
        score += 30
        reasons.append("Suspicious IP Subnet: Domain maps to bulletproof/threat-active network range")
    if ip_c.get("is_private"):
        score += 15
        reasons.append("Private IP Resolution: Resolves to an intranet address range (potential SSRF target)")

    # 5. Phishing heuristics
    phish_flags = phish.get("flags", [])
    if phish.get("typosquatting_detected"):
        score += 40
    if phish.get("exploit_detected"):
        score += 35

    for flag in phish_flags:
        reasons.append(flag)

    phish_count = phish.get("count", 0)
    if phish_count >= 3:
        score += 30
    elif phish_count >= 1:
        score += phish_count * 10

    # 6. HTML Forensics (Findings)
    html_findings = reach.get("html_findings", [])
    if html_findings:
        for finding in html_findings:
            reasons.append(finding)
        score += len(html_findings) * 20

    # 7. DNS & Email Spoofing
    if not dns_c.get("has_spf"):
        score += 10
        reasons.append("Missing SPF Record: Registry does not define authorized mailing servers")
    elif dns_c.get("spf_is_permissive"):
        score += 10
        reasons.append("Permissive SPF Config: Rule contains '+all' parameter allowing arbitrary sender spoofing")
    
    if not dns_c.get("has_dmarc"):
        score += 10
        reasons.append("Missing DMARC Record: Domain lacks email spoofing prevention controls")
    elif dns_c.get("dmarc_policy") == "none":
        score += 5
        reasons.append("Loose DMARC Policy: Configuration set to monitor-only ('p=none') leaving domain spoofable")

    # 8. Security Headers
    sec_headers = reach.get("security_headers", {})
    if sec_headers:
        header_score = sec_headers.get("score", 100)
        if header_score < 30:
            score += 10
            reasons.append("Missing Security Headers: Web server doesn't configure XSS, CSP, or HSTS headers")
        elif header_score < 60:
            score += 5
            reasons.append("Weak Response Headers: Missing standard web application hardening rules")

    # Cap score
    score = min(score, 100)

    if score >= 60:
        verdict = "DANGEROUS"
        verdict_color = "red"
        summary = "CRITICAL: High risk detected! This URL matches known threat patterns, cloning metrics, or phishing configurations."
    elif score >= 25:
        verdict = "SUSPICIOUS"
        verdict_color = "orange"
        summary = "WARNING: Link shows security omissions, unverified SSL configurations, or new registration details. Visit with caution."
    else:
        verdict = "SAFE"
        verdict_color = "green"
        summary = "CLEAN: Safe link. No threat signatures or phishing anomalies were found during structural diagnostics."

    return {
        "score": score,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "summary": summary,
        "reasons": list(set(reasons)),
    }


# ── Public APIs (Real-time Stream & Synchronous) ─────────────────────────────

def analyze_url_stream(raw_url: str):
    """
    Generator performing link security analysis step-by-step.
    Yields dicts describing current execution phase and partial results.
    """
    if not raw_url:
        yield {"step": "error", "message": "No URL provided", "status": "error"}
        return

    # 1. Domain extraction
    yield {
        "step": "init",
        "message": "Extracting destination domain and parsing syntax...",
        "status": "running"
    }
    try:
        url, domain = _extract_domain(raw_url)
        yield {
            "step": "init",
            "message": f"Verified target host domain: '{domain}'",
            "status": "success",
            "data": {"url": url, "domain": domain}
        }
    except Exception as e:
        yield {"step": "init", "message": f"URL parsing error: {e}", "status": "error"}
        return

    # 2. DNS
    yield {
        "step": "dns",
        "message": "Retrieving DNS records & email spoofing verification...",
        "status": "running"
    }
    dns_res = _check_dns_advanced(domain)
    dns_msg = "DNS records resolved successfully."
    if dns_res.get("issue"):
        dns_msg = f"DNS lookup partially failed: {dns_res['issue']}"
    yield {
        "step": "dns",
        "message": dns_msg,
        "status": "success" if not dns_res.get("issue") else "warning",
        "data": dns_res
    }

    # 3. IP reputation
    yield {
        "step": "ip",
        "message": "Querying domain IPv4 mapping & routing reputation...",
        "status": "running"
    }
    ip_res = _check_ip(domain)
    ip_msg = f"Resolved to IP: {ip_res.get('ip_address') or 'Unknown'}"
    if ip_res.get("issue"):
        ip_msg = f"Failed to resolve IP: {ip_res['issue']}"
    yield {
        "step": "ip",
        "message": ip_msg,
        "status": "success" if ip_res.get("ip_address") else "warning",
        "data": ip_res
    }

    # 4. SSL checks
    yield {
        "step": "ssl",
        "message": "Initiating secure SSL/TLS cryptographic handshake...",
        "status": "running"
    }
    ssl_res = _check_ssl_advanced(domain)
    ssl_msg = "SSL certificate active and verified." if ssl_res.get("valid_cert") else "SSL issues detected."
    if ssl_res.get("issue"):
        ssl_msg = f"SSL handshake warnings: {ssl_res['issue']}"
    yield {
        "step": "ssl",
        "message": ssl_msg,
        "status": "success" if ssl_res.get("valid_cert") else "warning",
        "data": ssl_res
    }

    # 5. Reachability and redirection
    yield {
        "step": "reachability",
        "message": "Testing endpoint reachability & following redirect chain...",
        "status": "running"
    }
    reach_res = _check_reachability(url)
    reach_msg = f"Endpoint responded with HTTP {reach_res.get('status_code') or 'Error'}"
    if reach_res.get("issue"):
        reach_msg = f"Connection failed: {reach_res['issue']}"
    yield {
        "step": "reachability",
        "message": reach_msg,
        "status": "success" if reach_res.get("reachable") else "warning",
        "data": reach_res
    }

    # 6. Phishing heuristics
    yield {
        "step": "phishing",
        "message": "Scanning URL geometry, homographs & typosquatting risk...",
        "status": "running"
    }
    phish_res = _check_phishing_signals(url, domain)
    phish_msg = f"Phishing check complete. Found {phish_res.get('count', 0)} threat flags."
    yield {
        "step": "phishing",
        "message": phish_msg,
        "status": "success" if phish_res.get("count", 0) == 0 else "warning",
        "data": phish_res
    }

    # 7. WHOIS Registry
    yield {
        "step": "domain_age",
        "message": "Querying WHOIS registries for domain ownership & age...",
        "status": "running"
    }
    age_res = _check_domain_age(domain)
    age_days = age_res.get("domain_age_days")
    age_msg = f"Domain age details retrieved. Registered: {age_res.get('registered_on') or 'Unknown'}"
    yield {
        "step": "domain_age",
        "message": age_msg,
        "status": "success" if age_days else "warning",
        "data": age_res
    }

    # 8. Verdict compiling
    yield {
        "step": "combine",
        "message": "Running security engine aggregation...",
        "status": "running"
    }
    checks = {
        "ssl": ssl_res,
        "reachability": reach_res,
        "domain_age": age_res,
        "ip": ip_res,
        "dns": dns_res,
        "phishing": phish_res,
    }
    verdict = _score_and_verdict(checks)
    
    yield {
        "step": "final",
        "message": "LinkGuard analysis compiled successfully.",
        "status": "success",
        "data": {
            "url": url,
            "domain": domain,
            "verdict": verdict,
            "checks": checks,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }
    }


def analyze_url(raw_url: str) -> dict:
    """
    Main entry point (synchronous wrapper).
    Runs the streaming analyzer generator and extracts the final dictionary payload.
    """
    final_payload = {}
    for event in analyze_url_stream(raw_url):
        if event["step"] == "final":
            final_payload = event["data"]
    return final_payload