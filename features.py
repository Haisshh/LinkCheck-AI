"""
features.py — Extraction de features à partir d'une URL + HTML optionnel.

Deux niveaux :
  - URL seule   : toujours disponible, instantané, pas de réseau
  - HTML        : optionnel — passé par analyzer.py si la requête a réussi

CORRECTIONS :
  - html_content peut être None → géré proprement partout
  - nb_subdomains corrigé ("google.com" = 0 sous-domaine, pas 2)
  - FEATURE_NAMES auto-généré depuis le dict → jamais désynchronisé
"""

import re
import math
from urllib.parse import urlparse

# ─────────────────────────────────────────────
# LISTES DE RÉFÉRENCE
# ─────────────────────────────────────────────

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "secure", "update", "urgent", "password",
    "confirm", "banking", "signin", "support", "wallet", "recovery",
    "helpdesk", "suspend", "alert", "billing", "authenticate", "credential",
    "webscr", "cmd", "dispatch", "ebayisapi"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "rebrand.ly", "shorturl.at",
    "cutt.ly", "bl.ink", "tiny.cc"
]

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click",
    "loan", "work", "party", "online", "site", "club", "info"
}

KNOWN_BRANDS = [
    "amazon", "google", "paypal", "apple", "microsoft", "facebook",
    "netflix", "ebay", "instagram", "whatsapp", "twitter", "linkedin",
    "dropbox", "adobe", "bankofamerica", "wellsfargo", "chase",
    "dhl", "fedex", "ups", "usps"
]

DANGEROUS_EXTENSIONS = {
    ".exe", ".zip", ".rar", ".js", ".vbs", ".php",
    ".sh", ".bat", ".cmd", ".ps1", ".msi", ".dmg"
}


# ─────────────────────────────────────────────
# UTILITAIRES
# ─────────────────────────────────────────────

def _words(text: str) -> list[str]:
    """Découpe en mots sur les séparateurs courants d'une URL."""
    return [w for w in re.split(r'[/\-_.?&=@+]', text) if w]


def _entropy(s: str) -> float:
    """Entropie de Shannon. Élevée = chaîne aléatoire/suspecte."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    t = len(s)
    return -sum((v / t) * math.log2(v / t) for v in freq.values())


def _safe_html(html_content) -> str:
    """
    Garantit une chaîne vide si html_content est None ou invalide.
    Évite les crashes sur .lower(), .count() etc.
    """
    if not html_content or not isinstance(html_content, str):
        return ""
    return html_content.lower()


# ─────────────────────────────────────────────
# EXTRACTION PRINCIPALE
# ─────────────────────────────────────────────

def extract_features(url: str, html_content=None) -> dict:
    """
    Extrait toutes les features.
    html_content est optionnel — peut être None si le site était inaccessible.
    """
    # Normalisation URL
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = "https://" + url

    parsed   = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    netloc   = (parsed.netloc or "").lower()
    path     = (parsed.path or "").lower()
    query    = (parsed.query or "").lower()
    full     = url.lower()

    # TLD et domaine principal
    parts  = hostname.split(".")
    tld    = parts[-1] if parts else ""
    domain = parts[-2] if len(parts) >= 2 else hostname

    # Sous-domaines : tout ce qui précède domain + TLD
    # CORRECTION : "google.com".split(".") = ["google","com"] → 0 sous-domaine
    # "secure.login.evil.com" → ["secure","login","evil","com"] → 2 sous-domaines
    subdomain_parts = parts[:-2] if len(parts) > 2 else []
    subdomain       = ".".join(subdomain_parts)
    nb_subdomains   = len(subdomain_parts)

    # HTML sécurisé (jamais None)
    html = _safe_html(html_content)
    has_html = len(html) > 0

    # ── Features URL ──────────────────────────────────────────────
    url_length      = len(url)
    hostname_length = len(hostname)
    path_length     = len(path)
    fd_length       = len(path.split("/")[1]) if len(path.split("/")) > 1 else 0
    tld_length      = len(tld)

    nb_dots       = full.count(".")
    nb_hyphens    = full.count("-")
    nb_at         = full.count("@")
    nb_qm         = full.count("?")
    nb_and        = full.count("&")
    nb_or         = full.count("|")
    nb_eq         = full.count("=")
    nb_underscore = full.count("_")
    nb_tilde      = full.count("~")
    nb_percent    = full.count("%")
    nb_slash      = full.count("/")
    nb_star       = full.count("*")
    nb_colon      = full.count(":")
    nb_comma      = full.count(",")
    nb_semicolumn = full.count(";")
    nb_dollar     = full.count("$")
    nb_space      = full.count(" ") + full.count("%20")
    nb_www        = int("www." in hostname)
    nb_com        = full.count(".com")
    nb_dslash     = max(0, full.count("//") - 1)
    http_in_path  = int("http" in path)
    https_token   = int("https" in hostname)

    nb_digits_url  = sum(c.isdigit() for c in full)
    nb_digits_host = sum(c.isdigit() for c in hostname)
    ratio_digits_url  = nb_digits_url  / url_length      if url_length      > 0 else 0.0
    ratio_digits_host = nb_digits_host / hostname_length if hostname_length > 0 else 0.0

    punycode  = int("xn--" in hostname)
    port      = int(parsed.port is not None and parsed.port not in (80, 443))

    tld_in_path      = int(f".{tld}" in path or f"/{tld}/" in path)
    tld_in_subdomain = int(tld in subdomain)
    abnormal_subdomain = int(nb_subdomains >= 3 or any(b in subdomain for b in KNOWN_BRANDS))
    prefix_suffix      = int("-" in domain)
    random_domain      = int(_entropy(domain) > 3.5 and len(domain) > 8)
    shortening_service = int(any(hostname == s or hostname.endswith("." + s) for s in SHORTENERS))
    path_extension     = int(any(path.endswith(ext) for ext in DANGEROUS_EXTENSIONS))

    nb_redirection = int(bool(re.search(r'(url|redirect|next|return)=https?://', full)))
    nb_external_redirection = max(0, full.count("http") - 1)

    words_url  = _words(full)
    words_host = _words(hostname)
    words_path = _words(path)

    def _stats(words):
        if not words:
            return 0, 0, 0.0
        L = [len(w) for w in words]
        return min(L), max(L), sum(L) / len(L)

    shortest_words_raw, longest_words_raw, avg_words_raw = _stats(words_url)
    shortest_word_host, longest_word_host, avg_word_host = _stats(words_host)
    shortest_word_path, longest_word_path, avg_word_path = _stats(words_path)
    length_words_raw = sum(len(w) for w in words_url)
    char_repeat = int(bool(re.search(r'(.)\1{3,}', full)))

    phish_hints        = sum(1 for w in SUSPICIOUS_WORDS if w in full)
    statistical_report = int(phish_hints >= 3)

    domain_in_brand    = 0
    brand_in_subdomain = 0
    brand_in_path      = 0
    has_brand_in_url   = 0
    for brand in KNOWN_BRANDS:
        if brand in hostname:
            has_brand_in_url = 1
            if not (hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com")):
                domain_in_brand = 1
        if brand in subdomain:
            brand_in_subdomain = 1
        if brand in path:
            brand_in_path = 1

    suspecious_tld = int(tld in SUSPICIOUS_TLDS)

    # ── Features HTML (calculées seulement si HTML disponible) ────
    # Si pas de HTML, on estime à partir des signaux URL (honnête approximation)
    if has_html:
        nb_hyperlinks  = html.count("<a href=")
        nb_forms       = html.count("<form")
        nb_iframe      = html.count("<iframe")
        nb_popups      = html.count("window.open")
        nb_rightClick  = int("event.button==2" in html or "contextmenu" in html)
        nb_onmouseover = html.count("onmouseover")
        nb_copyPaste   = int("oncopy" in html or "onpaste" in html)
        has_password_input = int('type="password"' in html or "type='password'" in html)

        # Liens internes vs externes
        all_links = re.findall(r'href=["\']([^"\']+)["\']', html)
        if all_links:
            ext = sum(1 for l in all_links if l.startswith("http") and hostname not in l)
            ratio_extHyperlinks  = ext / len(all_links)
            ratio_intHyperlinks  = 1 - ratio_extHyperlinks
            ratio_nullHyperlinks = sum(1 for l in all_links if l in ("#", "javascript:void(0)", "")) / len(all_links)
        else:
            ratio_extHyperlinks  = 0.0
            ratio_intHyperlinks  = 1.0
            ratio_nullHyperlinks = 0.0

        nb_extFormAction       = len(re.findall(r'action=["\']https?://', html))
        abnormal_extFormAction = int(nb_extFormAction > 0 and domain_in_brand)
        nb_extCSS              = html.count('<link rel="stylesheet"')
        nb_extRequests         = len(re.findall(r'src=["\']https?://', html))
        nb_extResources        = nb_extRequests
        nb_staticResources     = html.count("src=")
        nb_hints               = phish_hints
        nb_extNavigationalResources = int(nb_external_redirection > 0)
        nb_extImg              = len(re.findall(r'<img[^>]+src=["\']https?://', html))
    else:
        # Estimation depuis l'URL quand pas de HTML
        nb_hyperlinks  = min(50, url_length // 10)
        nb_forms       = int(phish_hints >= 2)
        nb_iframe      = int(nb_subdomains >= 2 or phish_hints >= 2)
        nb_popups      = int(phish_hints >= 2 or abnormal_subdomain)
        nb_rightClick  = int(phish_hints >= 3)
        nb_onmouseover = int(phish_hints >= 2)
        nb_copyPaste   = int(phish_hints >= 3)
        has_password_input = int("login" in full or "signin" in full or "password" in full)

        if domain_in_brand or abnormal_subdomain:
            ratio_extHyperlinks  = 0.8
            ratio_intHyperlinks  = 0.1
            ratio_nullHyperlinks = 0.1
            nb_extRequests       = 15
            nb_extResources      = 10
        else:
            ratio_extHyperlinks  = 0.2
            ratio_intHyperlinks  = 0.7
            ratio_nullHyperlinks = 0.1
            nb_extRequests       = 3
            nb_extResources      = 2

        nb_extFormAction            = int(domain_in_brand or brand_in_subdomain)
        abnormal_extFormAction      = nb_extFormAction
        nb_extCSS                   = int(domain_in_brand)
        nb_staticResources          = max(0, nb_hyperlinks - nb_extResources)
        nb_hints                    = phish_hints
        nb_extNavigationalResources = int(nb_external_redirection > 0 or domain_in_brand)
        nb_extImg                   = int(domain_in_brand or brand_in_subdomain)

    # Images de tracking (estimées)
    nb_extSmallImg                       = nb_extImg
    nb_extSmallImgFavicon                = nb_extImg
    nb_extSmallImgTotal                  = nb_extImg * 2
    nb_extSmallImgTotalFavicon           = nb_extImg
    nb_extSmallImgTotalRatio             = round(nb_extImg * 0.5, 2)
    nb_extSmallImgTotalRatioFavicon      = round(nb_extImg * 0.3, 2)
    nb_extSmallImgTotalRatioTotal        = round(nb_extImg * 0.4, 2)
    nb_extSmallImgTotalRatioTotalFavicon = round(nb_extImg * 0.2, 2)

    status_code = 200 if has_html else -1

    return {
        "url_length":                        url_length,
        "hostname_length":                   hostname_length,
        "path_length":                       path_length,
        "fd_length":                         fd_length,
        "tld_length":                        tld_length,
        "nb_dots":                           nb_dots,
        "nb_hyphens":                        nb_hyphens,
        "nb_at":                             nb_at,
        "nb_qm":                             nb_qm,
        "nb_and":                            nb_and,
        "nb_or":                             nb_or,
        "nb_eq":                             nb_eq,
        "nb_underscore":                     nb_underscore,
        "nb_tilde":                          nb_tilde,
        "nb_percent":                        nb_percent,
        "nb_slash":                          nb_slash,
        "nb_star":                           nb_star,
        "nb_colon":                          nb_colon,
        "nb_comma":                          nb_comma,
        "nb_semicolumn":                     nb_semicolumn,
        "nb_dollar":                         nb_dollar,
        "nb_space":                          nb_space,
        "nb_www":                            nb_www,
        "nb_com":                            nb_com,
        "nb_dslash":                         nb_dslash,
        "http_in_path":                      http_in_path,
        "https_token":                       https_token,
        "ratio_digits_url":                  ratio_digits_url,
        "ratio_digits_host":                 ratio_digits_host,
        "punycode":                          punycode,
        "port":                              port,
        "tld_in_path":                       tld_in_path,
        "tld_in_subdomain":                  tld_in_subdomain,
        "abnormal_subdomain":                abnormal_subdomain,
        "nb_subdomains":                     nb_subdomains,
        "prefix_suffix":                     prefix_suffix,
        "random_domain":                     random_domain,
        "shortening_service":                shortening_service,
        "path_extension":                    path_extension,
        "nb_redirection":                    nb_redirection,
        "nb_external_redirection":           nb_external_redirection,
        "length_words_raw":                  length_words_raw,
        "char_repeat":                       char_repeat,
        "shortest_words_raw":                shortest_words_raw,
        "shortest_word_host":                shortest_word_host,
        "shortest_word_path":                shortest_word_path,
        "longest_words_raw":                 longest_words_raw,
        "longest_word_host":                 longest_word_host,
        "longest_word_path":                 longest_word_path,
        "avg_words_raw":                     avg_words_raw,
        "avg_word_host":                     avg_word_host,
        "avg_word_path":                     avg_word_path,
        "phish_hints":                       phish_hints,
        "domain_in_brand":                   domain_in_brand,
        "brand_in_subdomain":                brand_in_subdomain,
        "brand_in_path":                     brand_in_path,
        "has_brand_in_url":                  has_brand_in_url,
        "suspecious_tld":                    suspecious_tld,
        "statistical_report":                statistical_report,
        "nb_hyperlinks":                     nb_hyperlinks,
        "nb_forms":                          nb_forms,
        "has_password_input":                has_password_input,
        "ratio_intHyperlinks":               ratio_intHyperlinks,
        "ratio_extHyperlinks":               ratio_extHyperlinks,
        "ratio_nullHyperlinks":              ratio_nullHyperlinks,
        "nb_extRequests":                    nb_extRequests,
        "nb_staticResources":                nb_staticResources,
        "nb_extResources":                   nb_extResources,
        "nb_hints":                          nb_hints,
        "nb_popups":                         nb_popups,
        "nb_iframe":                         nb_iframe,
        "nb_extFormAction":                  nb_extFormAction,
        "abnormal_extFormAction":            abnormal_extFormAction,
        "nb_rightClick":                     nb_rightClick,
        "nb_onmouseover":                    nb_onmouseover,
        "nb_copyPaste":                      nb_copyPaste,
        "nb_extNavigationalResources":       nb_extNavigationalResources,
        "nb_extImg":                         nb_extImg,
        "nb_extSmallImg":                    nb_extSmallImg,
        "nb_extSmallImgFavicon":             nb_extSmallImgFavicon,
        "nb_extSmallImgTotal":               nb_extSmallImgTotal,
        "nb_extSmallImgTotalFavicon":        nb_extSmallImgTotalFavicon,
        "nb_extSmallImgTotalRatio":          nb_extSmallImgTotalRatio,
        "nb_extSmallImgTotalRatioFavicon":   nb_extSmallImgTotalRatioFavicon,
        "nb_extSmallImgTotalRatioTotal":     nb_extSmallImgTotalRatioTotal,
        "nb_extSmallImgTotalRatioTotalFavicon": nb_extSmallImgTotalRatioTotalFavicon,
        "nb_extCSS":                         nb_extCSS,
        "status_code":                       status_code,
    }


# Auto-généré — toujours synchronisé avec le dict ci-dessus
FEATURE_NAMES = list(extract_features("https://example.com").keys())
