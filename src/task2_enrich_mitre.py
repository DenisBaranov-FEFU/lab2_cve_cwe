import asyncio
import aiohttp
import json
import os
import logging
import re
from pathlib import Path
from typing import Dict, List, Any

INPUT_FILE = "data/result_task_1.json"
OUTPUT_FILE = "data/result_task_2.json"
PROGRESS_FILE = "data/progress_task_2.json"

TIMEOUT_SEC = 15
MAX_CONCURRENT = 15
BATCH_SIZE = 50

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def recursive_search(data: Any, target_keys: List[str], results: List[Any] = None) -> List[Any]:
    """Рекурсивно ищет все значения по ключам в любом месте JSON."""
    if results is None:
        results = []
    if isinstance(data, dict):
        for key, value in data.items():
            if key in target_keys:
                results.append(value)
            recursive_search(value, target_keys, results)
    elif isinstance(data, list):
        for item in data:
            recursive_search(item, target_keys, results)
    return results

def find_cwe_objects(data: Any, results: List[dict] = None) -> List[dict]:
    """Рекурсивно ищет объекты-словари, содержащие ключ cweId."""
    if results is None:
        results = []
    if isinstance(data, dict):
        if "cweId" in data:
            results.append(data)
        for value in data.values():
            find_cwe_objects(value, results)
    elif isinstance(data, list):
        for item in data:
            find_cwe_objects(item, results)
    return results

class CVEProcessor:
    def __init__(self):
        self.processed_ids = self._load_progress()

    def _load_progress(self) -> set:
        if Path(PROGRESS_FILE).exists():
            try:
                with open(PROGRESS_FILE, 'r') as f:
                    return set(json.load(f))
            except Exception:
                pass
        return set()

    def _save_progress(self):
        Path(PROGRESS_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(PROGRESS_FILE, 'w') as f:
            json.dump(list(self.processed_ids), f)

    def extract_cvss_universal(self, mitre_data: dict) -> List[dict]:
        """Универсальный поиск CVSS в любом месте JSON."""
        cvss_list = []
        for version_key in ["cvssV3_1", "cvssV3_0", "cvssV2_0"]:
            cvss_data_list = recursive_search(mitre_data, [version_key])
            for cvss_data in cvss_data_list:
                if isinstance(cvss_data, dict):
                    severity = cvss_data.get("baseSeverity", " ")
                    cvss_list.append({
                        "version": version_key.lower(),
                        "score": cvss_data.get("baseScore"),
                        "vector": cvss_data.get("vectorString", " "),
                        "severity": str(severity).lower() if severity else "unknown"
                    })
        return cvss_list

    async def extract_cwe_data(self, mitre_data: dict, session: aiohttp.ClientSession) -> dict:
        """Извлекает данные CWE через cwe-api.mitre.org."""
        cwe_dict = {}
        
        # Собираем уникальные CWE ID из JSON
        cwe_ids = set()
        cwe_objects = find_cwe_objects(mitre_data)
        for obj in cwe_objects:
            cwe_id = obj.get("cweId")
            if cwe_id and isinstance(cwe_id, str) and cwe_id.startswith("CWE-"):
                cwe_ids.add(cwe_id)
                
        # Дополнительный поиск через recursive_search
        found_ids = recursive_search(mitre_data, ["cweId"])
        for cwe_id in found_ids:
            if isinstance(cwe_id, str) and cwe_id.startswith("CWE-"):
                cwe_ids.add(cwe_id)
                
        # Запрашиваем детали для каждого CWE
        for cwe_id in cwe_ids:
            cwe_num = cwe_id.replace("CWE-", "")
            url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_num}"
            
            try:
                async with session.get(url, timeout=TIMEOUT_SEC) as response:
                    if response.status == 200:
                        data = await response.json()
                        weakness_list = data.get("Weaknesses", [])
                        if weakness_list:
                            weakness = weakness_list[0]
                            
                            # 1. Name: берем и чистим от префикса CWE-XXX:
                            raw_name = weakness.get("Name", "Unknown")
                            clean_name = re.sub(r'^CWE-\d+[:\s\-]*', '', raw_name, flags=re.IGNORECASE).strip()
                            if not clean_name:
                                clean_name = "Not specified"
                                
                            # 2. Description: объединяем Description и ExtendedDescription
                            desc = weakness.get("Description", "")
                            ext_desc = weakness.get("ExtendedDescription", "")
                            full_desc = f"{desc} {ext_desc}".replace("\n", " ").strip()
                            if not full_desc:
                                full_desc = clean_name
                                
                            cwe_dict[cwe_id] = {
                                "name": clean_name,
                                "description": full_desc
                            }
                        else:
                            cwe_dict[cwe_id] = {"name": "Unknown", "description": "No data found"}
                    else:
                        cwe_dict[cwe_id] = {"name": "Unknown", "description": f"API returned {response.status}"}
            except Exception as e:
                logger.error(f"Ошибка CWE API для {cwe_id}: {e}")
                cwe_dict[cwe_id] = {"name": "Unknown", "description": "Could not fetch details"}
                
        return cwe_dict

    def extract_cpe_universal(self, mitre_data: dict) -> List[str]:
        """Универсальный поиск/синтез CPE."""
        cpe_list = []
        
        # 1. Ищем явные CPE
        cpe_data_list = recursive_search(mitre_data, ["cpes", "cpe"])
        for cpe_data in cpe_data_list:
            if isinstance(cpe_data, list):
                for cpe in cpe_data:
                    if isinstance(cpe, str) and cpe.startswith("cpe:"):
                        cpe_list.append(cpe)
        
        # 2. Если явных CPE нет, синтезируем из vendor/product
        if not cpe_list:
            affected_list = recursive_search(mitre_data, ["affected"])
            for affected in affected_list:
                if isinstance(affected, list):
                    for affected_item in affected:
                        if isinstance(affected_item, dict):
                            vendor = affected_item.get("vendor", " ")
                            product = affected_item.get("product", " ")
                            
                            if vendor and product and isinstance(vendor, str) and isinstance(product, str):
                                if vendor.lower() != "n/a" and product.lower() != "n/a":
                                    vendor_cpe = vendor.lower().replace(" ", "_").replace(".", "_")
                                    product_cpe = product.lower().replace(" ", "_").replace(".", "_")
                                    
                                    versions = recursive_search(affected_item, ["versions"])
                                    if versions:
                                        for ver_list in versions:
                                            if isinstance(ver_list, list):
                                                for version in ver_list:
                                                    if isinstance(version, dict):
                                                        ver_str = version.get("version", " ")
                                                        if ver_str and isinstance(ver_str, str) and ver_str.lower() != "n/a":
                                                            cpe_str = f"cpe:2.3:a:{vendor_cpe}:{product_cpe}:{ver_str}:*:*:*:*:*:*:*"
                                                            cpe_list.append(cpe_str)
                                    
                                    if not cpe_list:
                                        cpe_list.append(f"cpe:2.3:a:{vendor_cpe}:{product_cpe}:*:*:*:*:*:*:*:*")
        
        return list(set(cpe_list))

    async def process_cve(self, cve_id: str, vendor_data: dict, session: aiohttp.ClientSession) -> dict:
        api_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        
        try:
            async with session.get(api_url, timeout=TIMEOUT_SEC) as response:
                if response.status == 200:
                    mitre_data = await response.json()
                    meta = mitre_data.get("cveMetadata", {})
                    
                    cvss_list = self.extract_cvss_universal(mitre_data)
                    cpe_list = self.extract_cpe_universal(mitre_data)
                    cwe_dict = await self.extract_cwe_data(mitre_data, session)  # <-- Асинхронный вызов с передачей session
                    
                    desc_list = recursive_search(mitre_data, ["descriptions"])
                    description = "No description"
                    for desc_data in desc_list:
                        if isinstance(desc_data, list):
                            for d in desc_data:
                                if isinstance(d, dict) and d.get("lang") == "en":
                                    description = d.get("value", "No description")
                                    break
                            if description != "No description":
                                break
                    
                    return {
                        "ID": cve_id,
                        "vendor_release_date": str(vendor_data.get("vendor_release_date", "Unknown")),
                        "vendor_release_url": str(vendor_data.get("vendor_release_url", "Unknown")),
                        "url": f"https://www.cve.org/CVERecord?id={cve_id}",
                        "published_date": str(meta.get("datePublished", "Unknown")),
                        "updated_date": str(meta.get("dateUpdated", "Unknown")),
                        "description": str(description),
                        "cvss_list": cvss_list if cvss_list else [{"version": "N/A", "score": None, "vector": "N/A", "severity": "N/A"}],
                        "cpe_list": cpe_list if cpe_list else ["N/A"],
                        "cwe": cwe_dict if cwe_dict else {"N/A": {"name": "Not specified", "description": "No CWE data available in MITRE API"}}
                    }
                else:
                    return self._get_fallback(cve_id, vendor_data)
        except Exception as e:
            logger.error(f"Ошибка CVE {cve_id}: {e}")
            return self._get_fallback(cve_id, vendor_data)

    def _get_fallback(self, cve_id: str, vendor_data: dict) -> dict:
        return {
            "ID": cve_id,
            "vendor_release_date": str(vendor_data.get("vendor_release_date", "Unknown")),
            "vendor_release_url": str(vendor_data.get("vendor_release_url", "Unknown")),
            "url": f"https://www.cve.org/CVERecord?id={cve_id}",
            "published_date": "Unknown",
            "updated_date": "Unknown",
            "description": "Failed to fetch from MITRE API",
            "cvss_list": [{"version": "N/A", "score": None, "vector": "N/A", "severity": "N/A"}],
            "cpe_list": ["N/A"],
            "cwe": {"N/A": {"name": "Not specified", "description": "No CWE data available"}}
        }

    async def process_all(self, cve_list: List[dict]) -> List[dict]:
        to_process = [item for item in cve_list if item["ID"] not in self.processed_ids]
        logger.info(f"К обработке: {len(to_process)} из {len(cve_list)} CVE")
        
        results = []
        timeout = aiohttp.ClientTimeout(total=TIMEOUT_SEC)
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        
        async def bounded_process(item, sess):
            async with semaphore:
                return await self.process_cve(item["ID"], item, sess)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            for i in range(0, len(to_process), BATCH_SIZE):
                batch = to_process[i:i + BATCH_SIZE]
                tasks = [bounded_process(item, session) for item in batch]
                
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, dict) and result is not None:
                        results.append(result)
                        self.processed_ids.add(result["ID"])
                
                self._save_progress()
                
                if (i + BATCH_SIZE) % 500 == 0 or (i + BATCH_SIZE) >= len(to_process):
                    logger.info(f"Обработано: {len(self.processed_ids)}/{len(cve_list)}")
                
                await asyncio.sleep(0.2)
        
        return results

async def main_async():
    if not Path(INPUT_FILE).exists():
        logger.error(f"Файл {INPUT_FILE} не найден!")
        return
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        collected_data = json.load(f)

    logger.info(f"Загружено {len(collected_data)} CVE")
    processor = CVEProcessor()
    enriched_results = await processor.process_all(collected_data)

    # === ДЕДУПЛИКАЦИЯ ПО ID ===
    unique_results = {}
    for item in enriched_results:
        cve_id = item.get("ID")
        if cve_id and cve_id not in unique_results:
            unique_results[cve_id] = item

    final_results = list(unique_results.values())
    logger.info(f"После дедупликации: {len(final_results)} уникальных CVE (было {len(enriched_results)})")

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(final_results, f, ensure_ascii=False, indent=2)

    logger.info(f"Готово! Результат в {OUTPUT_FILE}")

def main():
    try:
        asyncio.run(main_async())
    except RuntimeError:
        import nest_asyncio
        nest_asyncio.apply()
        asyncio.run(main_async())

if __name__ == "__main__":
    main()
