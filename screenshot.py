import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

def take_screenshot(url, filename):
    # Création du dossier de stockage
    save_dir = "static/screenshots"
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    filepath = os.path.join(save_dir, f"{filename}.png")

    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Mode invisible
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--window-size=1280,720")
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

    driver = None
    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.set_page_load_timeout(20)
        driver.get(url)
        time.sleep(3)  # Attendre le chargement complet
        driver.save_screenshot(filepath)
        return filepath
    except Exception as e:
        print(f"Erreur screenshot : {e}")
        return None
    finally:
        if driver:
            driver.quit()