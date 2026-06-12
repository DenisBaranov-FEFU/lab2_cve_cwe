import json
import re
import os
import threading
from datetime import datetime
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set

import requests
from bs4 import BeautifulSoup
from dateutil import parser as date_parser
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from tqdm import tqdm

BASE_URL = "https://www.mozilla.org"
START_URL = "https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox/"
OUT_FILE = "data/result_task_1.json"
CACHE_FILE = "data/advisory_cache.json"
PROGRESS_FILE = "data/progress_task_1.json"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
MAX_WORKERS = 8
TIMEOUT = 30

cache_lock = threading.Lock()

def create_robust_session() -> requests.Session:
    session = requests.Session()
    retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
    return session

def load_progress() -> Set[str]:
    if os.path.exists(PROGRESS_FILE):
        try:
            with open(PROGRESS_FILE, 'r', encoding='utf-8') as f:
                return set(json.load(f))
        except Exception:
            pass
    return set()

def save_progress(processed_urls: Set[str]):
    os.makedirs(os.path.dirname(PROGRESS_FILE), exist_ok=True)
    with open(PROGRESS_FILE, 'w', encoding='utf-8') as f:
        json.dump(list(processed_urls), f)

def load_cache() -> Dict[str, List[Dict]]:
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_cache(cache: Dict[str, List[Dict]]):
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, 'w', encoding='utf-8') as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)

def get_soup(session: requests.Session, url: str) -> BeautifulSoup:
    response = session.get(url, timeout=TIMEOUT)
    response.raise_for_status()
    return BeautifulSoup(response.text, "lxml")

def normalize_date(value: str) -> str:
    dt = date_parser.parse(value.strip())
    return dt.date().isoformat()

def extract_advisory_links(session: requests.Session) -> List[str]:
    soup = get_soup(session, START_URL)
    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if "/security/advisories/mfsa" in href:
            links.add(urljoin(BASE_URL, href))
    return sorted(links)

def extract_date(soup: BeautifulSoup) -> str:
    text = soup.get_text("\n", strip=True)
    match = re.search(r"Announced\s+([A-Za-z]+\s+\d{1,2},\s+\d{4})", text)
    if not match:
        raise ValueError("Could not find advisory date")
    return normalize_date(match.group(1))

def parse_advisory(url: str, session: requests.Session) -> List[Dict]:
    soup = get_soup(session, url)
    vendor_date = extract_date(soup)
    text = soup.get_text("\n", strip=True)
    cves = sorted(set(CVE_RE.findall(text)))
    return [{"ID": cve, "vendor_release_date": vendor_date, "vendor_release_url": url} for cve in cves]

def process_advisory(url: str, session: requests.Session, cache: Dict[str, List[Dict]]) -> List[Dict]:
    with cache_lock:
        if url in cache:
            return cache[url]
    items = parse_advisory(url, session)
    with cache_lock:
        cache[url] = items
    return items

def main():
    processed_urls = load_progress()
    cache = load_cache()
    
    print("[INFO] Инициализация сессии...")
    session = create_robust_session()
    
    print("[INFO] Сбор ссылок на рекомендации...")
    advisory_links = extract_advisory_links(session)
    print(f"[INFO] Найдено рекомендаций: {len(advisory_links)}")
    
    to_process = [url for url in advisory_links if url not in processed_urls]
    print(f"[INFO] К обработке: {len(to_process)} (пропущено: {len(processed_urls)})")
    
    if not to_process:
        print("[INFO] Все advisory уже обработаны!")
        return
    
    result = []
    batch_size = 20
    
    print(f"[INFO] Запуск многопоточного сбора данных ({MAX_WORKERS} потоков)...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [(executor.submit(process_advisory, url, session, cache), url) for url in to_process]
        
        with tqdm(total=len(futures), desc="Обработка advisory") as pbar:
            for i, (future, url) in enumerate(futures, 1):
                try:
                    items = future.result()
                    result.extend(items)
                    processed_urls.add(url)
                    
                    if i % batch_size == 0:
                        save_progress(processed_urls)
                        save_cache(cache)
                    pbar.update(1)
                except Exception as exc:
                    tqdm.write(f"[ERROR] {url}: {exc}")
                    pbar.update(1)
    
    save_progress(processed_urls)
    save_cache(cache)
    
    # === ЖЕСТКАЯ ДЕДУПЛИКАЦИЯ ===
    final_dict = {}
    
    # 1. Сначала загружаем старые данные и кладем в словарь (ключ = (ID, url))
    if os.path.exists(OUT_FILE):
        try:
            with open(OUT_FILE, 'r', encoding='utf-8') as f:
                old_results = json.load(f)
            for item in old_results:
                key = (item.get("ID"), item.get("vendor_release_url"))
                if key[0] and key[1]:
                    final_dict[key] = item
        except Exception:
            pass
            
    # 2. Перезаписываем или добавляем новые данные (это удалит старые дубликаты)
    for item in result:
        key = (item["ID"], item["vendor_release_url"])
        final_dict[key] = item
        
    final_results = list(final_dict.values())
    final_results.sort(key=lambda x: (x["vendor_release_date"], x["ID"]))
    
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(final_results, f, ensure_ascii=False, indent=2)
    
    print(f"[DONE] Результаты ({len(final_results)} уникальных записей) сохранены в {OUT_FILE}")

if __name__ == "__main__":
    main()
