# features.py
# Extraction de features purement textuelles + HTML optionnel.
# Aucune requête réseau. Zéro dépendance externe.

import re
import math
from collections import Counter
from urllib.parse import urlparse
from functools import lru_cache
from typing import Optional

# ── Références (sets pour O(1) au lieu de O(n)) ───────────────────────────────

SUSPICIOUS_WORDS: frozenset[str] = frozenset({
    "login", "verify", "account", "secure", "update", "urgent", "password",
    "confirm", "banking", "signin", "support", "wallet", "recovery",
    "helpdesk", "suspend", "alert", "billing", "authenticate", "credential",
    "webscr", "cmd", "dispatch", "ebayisapi",
})

SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "rebrand.ly", "shorturl.at", "cutt.ly", "bl.ink", "tiny.cc",
})

SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click",
    "loan", "work", "party", "online", "site", "club", "info",
})

KNOWN_BRANDS: frozenset[str] = frozenset({
    "amazon", "google", "paypal", "apple", "microsoft", "facebook",
    "netflix", "ebay", "instagram", "whatsapp", "twitter", "linkedin",
    "dropbox", "adobe", "bankofamerica", "wellsfargo", "chase",
    "dhl", "fedex", "ups", "usps",
})

DANGEROUS_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".zip", ".rar", ".js", ".vbs", ".php",
    ".sh", ".bat", ".cmd", ".ps1", ".msi", ".dmg",
})

# ── Regex pré-compilées (compilées une fois au chargement du module) ───────────

_RE_NORMALIZE  = re.compile(r'^https?://', re.IGNORECASE)
_RE_SPLIT_WORD = re.compile(r'[/\-_.?&=@+]')
_RE_REPEAT     = re.compile(r'(.)\1{3,}')
_RE_REDIRECT   = re.compile(r'(?:url|redirect|next|return)=https?://', re.IGNORECASE)
_RE_HREF       = re.compile(r'href=["\']([^"\']*)["\']')
_RE_ACTION     = re.compile(r'action=["\']https?://')
_RE_SRC        = re.compile(r'src=["\']https?://')
_RE_EXT_IMG    = re.compile(r'<img[^>]+src=["\']https?://')

# ── Utilitaires ───────────────────────────────────────────────────────────────

def _safe_lower(s: Optional[str]) -> str:
    """None-safe lowercase. Retourne '' si None ou non-str."""
    return s.lower() if isinstance(s, str) and s else ""


def _entropy(s: str) -> float:
    """Entropie de Shannon. Valeur haute = chaîne aléatoire."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    t = len(s)
    return -sum((v / t) * math.log2(v / t) for v in freq.values())


def _word_stats(text: str) -> tuple[int, int, float]:
    """Retourne (min_len, max_len, avg_len) des mots d'un segment d'URL."""
    words = [w for w in _RE_SPLIT_WORD.split(text) if w]
    if not words:
        return 0, 0, 0.0
    lengths = [len(w) for w in words]
    return min(lengths), max(lengths), sum(lengths) / len(lengths)


# ── Extraction principale ─────────────────────────────────────────────────────

def extract_features(url: str, html_content: Optional[str] = None) -> dict:
    """
    Retourne un dict de features numériques.
    html_content est optionnel — None si le site était inaccessible.
    Aucune requête réseau effectuée ici.
    """
    # ── Normalisation ─────────────────────────────────────────────
    if not _RE_NORMALIZE.match(url):
        url = "https://" + url

    parsed   = urlparse(url)
    hostname = _safe_lower(parsed.hostname)
    path     = _safe_lower(parsed.path)
    query    = _safe_lower(parsed.query)
    full     = url.lower()

    # Décomposition du domaine
    parts           = hostname.split(".")
    tld             = parts[-1] if parts else ""
    domain          = parts[-2] if len(parts) >= 2 else hostname
    subdomain_parts = parts[:-2] if len(parts) > 2 else []
    subdomain       = ".".join(subdomain_parts)
    nb_subdomains   = len(subdomain_parts)

    # HTML normalisé (jamais None)
    html     = _safe_lower(html_content)
    has_html = bool(html)

    # ── Longueurs ─────────────────────────────────────────────────
    url_len  = len(url)
    host_len = len(hostname)
    path_len = len(path)
    tld_len  = len(tld)
    fd_len   = len(path.split("/")[1]) if len(path.split("/")) > 1 else 0

    # ── Comptage de caractères (un seul passage sur full) ─────────
    counter = Counter(full)
    nb_dots      = counter["."]
    nb_hyphens   = counter["-"]
    nb_at        = counter["@"]
    nb_qm        = counter["?"]
    nb_and       = counter["&"]
    nb_or        = counter["|"]
    nb_eq        = counter["="]
    nb_underscore= counter["_"]
    nb_tilde     = counter["~"]
    nb_percent   = counter["%"]
    nb_slash     = counter["/"]
    nb_star      = counter["*"]
    nb_colon     = counter[":"]
    nb_comma     = counter[","]
    nb_semicolumn= counter[";"]
    nb_dollar    = counter["$"]
    nb_space     = counter[" "] + full.count("%20")

    nb_www    = int("www." in hostname)
    nb_com    = full.count(".com")
    nb_dslash = max(0, full.count("//") - 1)

    http_in_path = int("http" in path)
    https_token  = int("https" in hostname)

    nb_digits_url  = sum(1 for c in full     if c.isdigit())
    nb_digits_host = sum(1 for c in hostname if c.isdigit())
    ratio_digits_url  = nb_digits_url  / url_len  if url_len  else 0.0
    ratio_digits_host = nb_digits_host / host_len if host_len else 0.0

    punycode = int("xn--" in hostname)
    port     = int(parsed.port is not None and parsed.port not in (80, 443))

    # ── Signaux structurels ────────────────────────────────────────
    tld_in_path      = int(f".{tld}" in path or f"/{tld}/" in path)
    tld_in_subdomain = int(tld in subdomain)
    prefix_suffix    = int("-" in domain)
    random_domain    = int(_entropy(domain) > 3.5 and len(domain) > 8)
    shortening_svc   = int(hostname in SHORTENERS or
                           any(hostname.endswith("." + s) for s in SHORTENERS))
    path_extension   = int(any(path.endswith(ext) for ext in DANGEROUS_EXTENSIONS))

    nb_redirection          = int(bool(_RE_REDIRECT.search(full)))
    nb_external_redirection = max(0, full.count("http") - 1)

    char_repeat = int(bool(_RE_REPEAT.search(full)))

    # ── Mots suspects (un seul passage sur SUSPICIOUS_WORDS) ──────
    phish_hints        = sum(1 for w in SUSPICIOUS_WORDS if w in full)
    statistical_report = int(phish_hints >= 3)

    # ── Statistiques sur les mots ──────────────────────────────────
    sh_raw, lg_raw, avg_raw   = _word_stats(full)
    sh_host, lg_host, avg_host = _word_stats(hostname)
    sh_path, lg_path, avg_path = _word_stats(path)
    len_words_raw = sum(len(w) for w in _RE_SPLIT_WORD.split(full) if w)

    # ── Marques (un seul passage) ──────────────────────────────────
    domain_in_brand = brand_in_subdomain = brand_in_path = has_brand = 0
    abnormal_subdomain = int(nb_subdomains >= 3)

    for brand in KNOWN_BRANDS:
        if brand in hostname:
            has_brand = 1
            if not (hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com")):
                domain_in_brand = 1
            if brand in subdomain:
                brand_in_subdomain = 1
                abnormal_subdomain = 1
        if brand in path:
            brand_in_path = 1

    suspecious_tld = int(tld in SUSPICIOUS_TLDS)

    # ── Features HTML ──────────────────────────────────────────────
    if has_html:
        nb_hyperlinks  = html.count("<a href=")
        nb_forms       = html.count("<form")
        nb_iframe      = html.count("<iframe")
        nb_popups      = html.count("window.open")
        nb_rightClick  = int("event.button==2" in html or "contextmenu" in html)
        nb_onmouseover = html.count("onmouseover")
        nb_copyPaste   = int("oncopy" in html or "onpaste" in html)
        has_pw         = int('type="password"' in html or "type='password'" in html)

        links = _RE_HREF.findall(html)
        if links:
            n_ext = sum(1 for l in links if l.startswith("http") and hostname not in l)
            ratio_ext  = n_ext / len(links)
            ratio_int  = 1.0 - ratio_ext
            ratio_null = sum(1 for l in links if l in ("#", "javascript:void(0)", "")) / len(links)
        else:
            ratio_ext = ratio_null = 0.0
            ratio_int = 1.0

        nb_ext_form    = len(_RE_ACTION.findall(html))
        abn_form       = int(nb_ext_form > 0 and domain_in_brand)
        nb_ext_css     = html.count('<link rel="stylesheet"')
        nb_ext_req     = len(_RE_SRC.findall(html))
        nb_ext_res     = nb_ext_req
        nb_static      = html.count("src=")
        nb_ext_nav     = int(nb_external_redirection > 0)
        nb_ext_img     = len(_RE_EXT_IMG.findall(html))
        status_code    = 200
    else:
        # Estimation URL-only quand HTML absent
        nb_hyperlinks  = min(50, url_len // 10)
        nb_forms       = int(phish_hints >= 2)
        nb_iframe      = int(nb_subdomains >= 2 or phish_hints >= 2)
        nb_popups      = int(phish_hints >= 2 or abnormal_subdomain)
        nb_rightClick  = int(phish_hints >= 3)
        nb_onmouseover = int(phish_hints >= 2)
        nb_copyPaste   = int(phish_hints >= 3)
        has_pw         = int(any(w in full for w in ("login", "signin", "password")))

        suspicious_site = bool(domain_in_brand or abnormal_subdomain)
        ratio_ext       = 0.8 if suspicious_site else 0.2
        ratio_int       = 1.0 - ratio_ext
        ratio_null      = 0.1
        nb_ext_req      = 15 if suspicious_site else 3
        nb_ext_res      = 10 if suspicious_site else 2
        nb_ext_form     = int(domain_in_brand or brand_in_subdomain)
        abn_form        = nb_ext_form
        nb_ext_css      = int(domain_in_brand)
        nb_static       = max(0, nb_hyperlinks - nb_ext_res)
        nb_ext_nav      = int(nb_external_redirection > 0 or domain_in_brand)
        nb_ext_img      = int(domain_in_brand or brand_in_subdomain)
        status_code     = -1

    # Images de tracking dérivées
    nb_sm          = nb_ext_img
    nb_sm_total    = nb_ext_img * 2
    r_sm           = round(nb_ext_img * 0.5, 2)
    r_sm_fav       = round(nb_ext_img * 0.3, 2)
    r_sm_total     = round(nb_ext_img * 0.4, 2)
    r_sm_total_fav = round(nb_ext_img * 0.2, 2)

    return {
        "url_length":                          url_len,
        "hostname_length":                     host_len,
        "path_length":                         path_len,
        "fd_length":                           fd_len,
        "tld_length":                          tld_len,
        "nb_dots":                             nb_dots,
        "nb_hyphens":                          nb_hyphens,
        "nb_at":                               nb_at,
        "nb_qm":                               nb_qm,
        "nb_and":                              nb_and,
        "nb_or":                               nb_or,
        "nb_eq":                               nb_eq,
        "nb_underscore":                       nb_underscore,
        "nb_tilde":                            nb_tilde,
        "nb_percent":                          nb_percent,
        "nb_slash":                            nb_slash,
        "nb_star":                             nb_star,
        "nb_colon":                            nb_colon,
        "nb_comma":                            nb_comma,
        "nb_semicolumn":                       nb_semicolumn,
        "nb_dollar":                           nb_dollar,
        "nb_space":                            nb_space,
        "nb_www":                              nb_www,
        "nb_com":                              nb_com,
        "nb_dslash":                           nb_dslash,
        "http_in_path":                        http_in_path,
        "https_token":                         https_token,
        "ratio_digits_url":                    ratio_digits_url,
        "ratio_digits_host":                   ratio_digits_host,
        "punycode":                            punycode,
        "port":                                port,
        "tld_in_path":                         tld_in_path,
        "tld_in_subdomain":                    tld_in_subdomain,
        "abnormal_subdomain":                  abnormal_subdomain,
        "nb_subdomains":                       nb_subdomains,
        "prefix_suffix":                       prefix_suffix,
        "random_domain":                       random_domain,
        "shortening_service":                  shortening_svc,
        "path_extension":                      path_extension,
        "nb_redirection":                      nb_redirection,
        "nb_external_redirection":             nb_external_redirection,
        "length_words_raw":                    len_words_raw,
        "char_repeat":                         char_repeat,
        "shortest_words_raw":                  sh_raw,
        "shortest_word_host":                  sh_host,
        "shortest_word_path":                  sh_path,
        "longest_words_raw":                   lg_raw,
        "longest_word_host":                   lg_host,
        "longest_word_path":                   lg_path,
        "avg_words_raw":                       avg_raw,
        "avg_word_host":                       avg_host,
        "avg_word_path":                       avg_path,
        "phish_hints":                         phish_hints,
        "domain_in_brand":                     domain_in_brand,
        "brand_in_subdomain":                  brand_in_subdomain,
        "brand_in_path":                       brand_in_path,
        "has_brand_in_url":                    has_brand,
        "suspecious_tld":                      suspecious_tld,
        "statistical_report":                  statistical_report,
        "nb_hyperlinks":                       nb_hyperlinks,
        "nb_forms":                            nb_forms,
        "has_password_input":                  has_pw,
        "ratio_intHyperlinks":                 ratio_int,
        "ratio_extHyperlinks":                 ratio_ext,
        "ratio_nullHyperlinks":                ratio_null,
        "nb_extRequests":                      nb_ext_req,
        "nb_staticResources":                  nb_static,
        "nb_extResources":                     nb_ext_res,
        "nb_hints":                            phish_hints,
        "nb_popups":                           nb_popups,
        "nb_iframe":                           nb_iframe,
        "nb_extFormAction":                    nb_ext_form,
        "abnormal_extFormAction":              abn_form,
        "nb_rightClick":                       nb_rightClick,
        "nb_onmouseover":                      nb_onmouseover,
        "nb_copyPaste":                        nb_copyPaste,
        "nb_extNavigationalResources":         nb_ext_nav,
        "nb_extImg":                           nb_ext_img,
        "nb_extSmallImg":                      nb_sm,
        "nb_extSmallImgFavicon":               nb_sm,
        "nb_extSmallImgTotal":                 nb_sm_total,
        "nb_extSmallImgTotalFavicon":          nb_sm,
        "nb_extSmallImgTotalRatio":            r_sm,
        "nb_extSmallImgTotalRatioFavicon":     r_sm_fav,
        "nb_extSmallImgTotalRatioTotal":       r_sm_total,
        "nb_extSmallImgTotalRatioTotalFavicon":r_sm_total_fav,
        "nb_extCSS":                           nb_ext_css,
        "status_code":                         status_code,
    }


# Généré automatiquement — toujours synchronisé avec le dict ci-dessus
FEATURE_NAMES: list[str] = list(extract_features("https://example.com").keys())