# screenshot.py
# Asynchronous screenshot capture using Selenium Chrome headless.
# Single worker - never multiple Chrome instances in parallel.
# Flask is never blocked.

import os
import re
import time
import logging
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Optional

from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

logger    = logging.getLogger("linkcheck.screenshot")
_POOL     = ThreadPoolExecutor(max_workers=2, thread_name_prefix="screenshot")
_SHOT_DIR = os.path.join("static", "screenshots")
_RE_SAFE  = re.compile(r'[^a-zA-Z0-9\-]')

_CHROME_ARGS = (
    "--headless=new",
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--window-size=1280,720",
    "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
)


def _do_capture(url: str, path: str) -> Optional[str]:
    """Runs in the worker thread. Never called directly from Flask."""
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import TimeoutException, WebDriverException

    opts = Options()
    for arg in _CHROME_ARGS:
        opts.add_argument(arg)

    driver = None
    t0     = time.monotonic()
    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=opts)
        driver.set_page_load_timeout(15)
        driver.get(url)
        time.sleep(2)
        driver.save_screenshot(path)
        logger.info("[screenshot] OK %.1fs -> %s", time.monotonic() - t0, path)
        return path

    except TimeoutException:
        logger.warning("[screenshot] Timeout >15s : %s", url)
    except WebDriverException as e:
        first_line = str(e).split("\n")[0]
        if "ERR_NAME_NOT_RESOLVED" in first_line:
            logger.warning("[screenshot] Domain not found: %s", url)
        elif "ERR_CONNECTION_REFUSED" in first_line:
            logger.warning("[screenshot] Connection refused: %s", url)
        elif "ERR_CONNECTION_TIMED_OUT" in first_line:
            logger.warning("[screenshot] Connection timed out: %s", url)
        elif "session not created" in first_line.lower():
            logger.error("[screenshot] Chrome not found - install Chromium")
        else:
            logger.error("[screenshot] WebDriver error: %s", first_line)
    except Exception as e:
        logger.error("[screenshot] %s : %s", type(e).__name__, e)
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
    return None


def take_screenshot_async(url: str, filename: Optional[str] = None) -> Future:
    """
    Schedule a capture in the worker thread and return immediately.
    Flask can handle other requests while this is running.
    The result is available via GET /screenshot/<hostname>.
    """
    os.makedirs(_SHOT_DIR, exist_ok=True)

    if not filename:
        filename = _RE_SAFE.sub("_", url)[:60]

    filepath = os.path.join(_SHOT_DIR, f"{filename}.png")

    # Cache: skip Chrome if the image already exists
    if os.path.exists(filepath):
        logger.debug("[screenshot] Cache hit : %s", filepath)
        return _POOL.submit(lambda: filepath)

    logger.info("[screenshot] Scheduled: %s", url)
    return _POOL.submit(_do_capture, url, filepath)