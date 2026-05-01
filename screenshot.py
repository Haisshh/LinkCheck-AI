"""
screenshot.py — Capture d'écran non bloquante via un thread dédié.

CORRECTIONS :
  - La capture tourne dans un ThreadPoolExecutor séparé → Flask n'est
    JAMAIS bloqué. Les autres requêtes sont servies pendant ce temps.
  - Un seul worker dans le pool : pas de 10 Chrome en parallèle.
  - Logs détaillés : timeout, connexion refusée, Chrome manquant...
  - Cache : si la capture existe déjà, on ne relance pas Chrome.
"""

import os
import re
import time
import logging
from concurrent.futures import ThreadPoolExecutor

# Pool d'UN seul worker → un seul Chrome à la fois, jamais en parallèle
_executor = ThreadPoolExecutor(max_workers=1)

SCREENSHOT_DIR = os.path.join("static", "screenshots")

logger = logging.getLogger("linkcheck.screenshot")


def _build_filename(url: str) -> str:
    clean = re.sub(r'[^a-zA-Z0-9\-]', '_', url)
    return clean[:60]


def _do_capture(url: str, filepath: str) -> str | None:
    """Exécutée dans le thread secondaire — jamais dans le thread Flask."""
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import TimeoutException, WebDriverException

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1280,720")
    options.add_argument(
        "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
    )

    driver = None
    t0 = time.time()
    try:
        logger.info(f"[screenshot] Démarrage Chrome pour : {url}")
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(15)
        driver.get(url)
        time.sleep(2)
        driver.save_screenshot(filepath)
        elapsed = round(time.time() - t0, 1)
        logger.info(f"[screenshot] Capture OK en {elapsed}s → {filepath}")
        return filepath

    except TimeoutException:
        logger.warning(f"[screenshot] Timeout (>15s) — le site ne répond pas : {url}")
        return None
    except WebDriverException as e:
        msg = str(e).split("\n")[0]  # première ligne seulement, pas de stack complète
        if "net::ERR_NAME_NOT_RESOLVED" in msg:
            logger.warning(f"[screenshot] Domaine inexistant : {url}")
        elif "net::ERR_CONNECTION_REFUSED" in msg:
            logger.warning(f"[screenshot] Connexion refusée : {url}")
        elif "net::ERR_CONNECTION_TIMED_OUT" in msg:
            logger.warning(f"[screenshot] Connexion expirée : {url}")
        elif "chrome not reachable" in msg.lower() or "session not created" in msg.lower():
            logger.error("[screenshot] Chrome introuvable — vérifiez que Chromium est installé")
        else:
            logger.error(f"[screenshot] Erreur WebDriver : {msg}")
        return None
    except Exception as e:
        logger.error(f"[screenshot] Erreur inattendue : {type(e).__name__}: {e}")
        return None
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass


def take_screenshot_async(url: str, filename: str = None):
    """
    Lance la capture dans un thread secondaire et retourne un Future.
    Flask continue de répondre aux autres requêtes pendant ce temps.

    Utilisation dans analyzer.py :
        future = take_screenshot_async(url, name)
        # ... on peut faire autre chose ...
        path = future.result(timeout=30)  # attend max 30s si nécessaire
    """
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    if filename is None:
        filename = _build_filename(url)

    filepath = os.path.join(SCREENSHOT_DIR, f"{filename}.png")

    # Cache : si la capture existe déjà, on retourne un Future déjà résolu
    if os.path.exists(filepath):
        logger.debug(f"[screenshot] Cache hit : {filepath}")
        future = _executor.submit(lambda: filepath)
        return future

    logger.info(f"[screenshot] Capture planifiée (async) pour : {url}")
    return _executor.submit(_do_capture, url, filepath)
