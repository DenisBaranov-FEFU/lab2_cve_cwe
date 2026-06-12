import json
import xml.etree.ElementTree as ET
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

IN_FILE = "data/result_task_2.json"
OUT_FILE = "data/result_task_3.xml"

def main():
    logger.info(f"Загрузка данных из {IN_FILE}...")
    try:
        with open(IN_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logger.error(f"Не удалось прочитать JSON: {e}")
        return

    if not isinstance(data, list) or len(data) == 0:
        logger.error("Файл JSON пуст или имеет неверный формат.")
        return

    # === ДОПОЛНИТЕЛЬНАЯ ДЕДУПЛИКАЦИЯ ПЕРЕД ГЕНЕРАЦИЕЙ XML ===
    seen_ids = set()
    unique_data = []
    duplicates = 0
    
    for item in data:
        cve_id = item.get("ID")
        if cve_id and cve_id not in seen_ids:
            seen_ids.add(cve_id)
            unique_data.append(item)
        else:
            duplicates += 1
    
    if duplicates > 0:
        logger.warning(f"Найдено и удалено {duplicates} дубликатов перед генерацией XML")
    
    logger.info(f"Обработано {len(unique_data)} уникальных записей. Генерация XML...")
    
    root = ET.Element("vulnerabilities")
    stats = {"cvss": 0, "cpe": 0, "cwe": 0}

    for item in unique_data:
        if not isinstance(item, dict):
            continue

        vuln = ET.SubElement(root, "vulnerability")

        for field in ["ID", "vendor_release_date", "vendor_release_url", 
                      "url", "published_date", "updated_date", "description"]:
            val = item.get(field)
            elem = ET.SubElement(vuln, field)
            elem.text = str(val) if val is not None else ""

        cvss_list_elem = ET.SubElement(vuln, "cvss_list")
        cvss_data = item.get("cvss_list", [])
        if isinstance(cvss_data, list):
            for cvss in cvss_data:
                if isinstance(cvss, dict):
                    ET.SubElement(cvss_list_elem, "cvss", {
                        "version": str(cvss.get("version", "")),
                        "score": str(cvss.get("score", "")),
                        "severity": str(cvss.get("severity", ""))
                    }).text = str(cvss.get("vector", ""))
                    stats["cvss"] += 1

        cpe_list_elem = ET.SubElement(vuln, "cpe_list")
        cpe_data = item.get("cpe_list", [])
        if isinstance(cpe_data, list):
            for cpe in cpe_data:
                ET.SubElement(cpe_list_elem, "cpe").text = str(cpe)
                stats["cpe"] += 1

        cwe_list_elem = ET.SubElement(vuln, "cwe_list")
        cwe_data = item.get("cwe", {})
        if isinstance(cwe_data, dict):
            for cwe_id, cwe_info in cwe_data.items():
                if isinstance(cwe_info, dict):
                    ET.SubElement(cwe_list_elem, "cwe", {
                        "id": str(cwe_id),
                        "name": str(cwe_info.get("name", ""))
                    }).text = str(cwe_info.get("description", ""))
                    stats["cwe"] += 1

    logger.info(f"Сгенерировано XML: {len(unique_data)} уязвимостей, CVSS: {stats['cvss']}, CPE: {stats['cpe']}, CWE: {stats['cwe']}")

    tree = ET.ElementTree(root)
    try:
        ET.indent(tree, space="  ", level=0)
    except AttributeError:
        pass
        
    tree.write(OUT_FILE, encoding="utf-8", xml_declaration=True)
    logger.info(f"[DONE] XML сохранен в {OUT_FILE}")

if __name__ == "__main__":
    main()
