import json
import pandas as pd
from sqlalchemy import create_engine, text
import logging
import time

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

JSON_FILE = "data/result_task_2.json"
DB_URL = "postgresql://cveuser:cvepass@127.0.0.1:5432/cvedb"
OUTPUT_FILE = "data/Report.xlsx"

def load_json_to_db(engine):
    logger.info(f"Загрузка данных из {JSON_FILE} в БД...")
    
    with open(JSON_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Дедупликация перед загрузкой
    seen_ids = set()
    unique_data = []
    for item in data:
        cve_id = item.get("ID")
        if cve_id and cve_id not in seen_ids:
            seen_ids.add(cve_id)
            unique_data.append(item)
    
    if len(unique_data) < len(data):
        logger.warning(f"Удалено {len(data) - len(unique_data)} дубликатов перед загрузкой в БД")
    
    total = len(unique_data)
    logger.info(f"Найдено {total} уникальных записей")
    
    stats = {"cves": 0, "cpes": 0, "cwes": 0, "errors": 0}
    start_time = time.time()
    
    with engine.connect() as conn:
        conn.execute(text("TRUNCATE TABLE cve_cpe, cve_cwe, cves, cpes, cwes CASCADE"))
        conn.commit()
        
        for idx, item in enumerate(unique_data, 1):
            try:
                cve_id = item.get("ID")
                if not cve_id:
                    continue
                
                cvss_list = item.get("cvss_list", [])
                score = None
                severity = "UNKNOWN"
                for cvss in cvss_list:
                    if isinstance(cvss, dict) and cvss.get("score") is not None:
                        score = cvss.get("score")
                        severity = cvss.get("severity", "UNKNOWN").upper()
                        break
                
                conn.execute(text("""
                    INSERT INTO cves (id, vendor_release_date, vendor_release_url, published_date, description, score, severity)
                    VALUES (:id, :vendor_date, :vendor_url, :pub_date, :desc, :score, :severity)
                    ON CONFLICT (id) DO NOTHING
                """), {
                    "id": cve_id,
                    "vendor_date": item.get("vendor_release_date"),
                    "vendor_url": item.get("vendor_release_url"),
                    "pub_date": item.get("published_date"),
                    "desc": item.get("description"),
                    "score": score,
                    "severity": severity
                })
                stats["cves"] += 1
                
                cpe_list = item.get("cpe_list", [])
                for cpe_str in cpe_list:
                    if not cpe_str or cpe_str == "N/A":
                        continue
                    result = conn.execute(text("""
                        INSERT INTO cpes (cpe_string) VALUES (:cpe)
                        ON CONFLICT (cpe_string) DO NOTHING
                        RETURNING id
                    """), {"cpe": cpe_str})
                    cpe_id = result.scalar()
                    
                    if not cpe_id:
                        cpe_id = conn.execute(text("SELECT id FROM cpes WHERE cpe_string = :cpe"), {"cpe": cpe_str}).scalar()
                    
                    if cpe_id:
                        conn.execute(text("""
                            INSERT INTO cve_cpe (cve_id, cpe_id) VALUES (:cve_id, :cpe_id)
                            ON CONFLICT DO NOTHING
                        """), {"cve_id": cve_id, "cpe_id": cpe_id})
                        stats["cpes"] += 1
                
                cwe_dict = item.get("cwe", {})
                if isinstance(cwe_dict, dict):
                    for cwe_id_val, cwe_info in cwe_dict.items():
                        if not cwe_id_val or cwe_id_val == "N/A" or not isinstance(cwe_info, dict):
                            continue
                        cwe_name = cwe_info.get("name", "Unknown")
                        cwe_desc = cwe_info.get("description", "")
                        
                        result = conn.execute(text("""
                            INSERT INTO cwes (id, name, description) VALUES (:id, :name, :desc)
                            ON CONFLICT (id) DO NOTHING
                            RETURNING id
                        """), {"id": cwe_id_val, "name": cwe_name, "desc": cwe_desc})
                        inserted_id = result.scalar()
                        
                        if not inserted_id:
                            inserted_id = conn.execute(text("SELECT id FROM cwes WHERE id = :id"), {"id": cwe_id_val}).scalar()
                        
                        if inserted_id:
                            conn.execute(text("""
                                INSERT INTO cve_cwe (cve_id, cwe_id) VALUES (:cve_id, :cwe_id)
                                ON CONFLICT DO NOTHING
                            """), {"cve_id": cve_id, "cwe_id": inserted_id})
                            stats["cwes"] += 1
                
                conn.commit()
                
            except Exception as e:
                stats["errors"] += 1
                conn.rollback()
        
        elapsed = time.time() - start_time
        
        logger.info(f"\n[✅ DONE] Загрузка завершена за {elapsed:.1f}с")
        logger.info(f"[📊 Статистика]")
        logger.info(f"  • CVE: {stats['cves']}")
        logger.info(f"  • CPE: {stats['cpes']}")
        logger.info(f"  • CWE: {stats['cwes']}")
        if stats["errors"] > 0:
            logger.info(f"  • Ошибки: {stats['errors']}")

def export_to_excel(engine):
    logger.info("Экспорт данных из БД в Excel...")
    
    query = """
    SELECT 
        c.id AS "CVE ID",
        c.vendor_release_date AS "Vendor Release Date",
        c.vendor_release_url AS "Vendor URL",
        c.published_date AS "NVD Published Date",
        c.description AS "Description",
        c.score AS "CVSS Score",
        c.severity AS "Severity",
        STRING_AGG(DISTINCT cp.cpe_string, ', ') AS "Affected CPEs",
        STRING_AGG(DISTINCT (cw.id || ': ' || cw.name), ' | ') AS "CWE Classes"
    FROM cves c
    LEFT JOIN cve_cpe j_cp ON c.id = j_cp.cve_id
    LEFT JOIN cpes cp ON j_cp.cpe_id = cp.id
    LEFT JOIN cve_cwe j_cw ON c.id = j_cw.cwe_id
    LEFT JOIN cwes cw ON j_cw.cwe_id = cw.id
    GROUP BY c.id, c.vendor_release_date, c.vendor_release_url, c.published_date, c.description, c.score, c.severity
    ORDER BY c.id DESC;
    """
    
    df = pd.read_sql_query(query, engine)
    df.to_excel(OUTPUT_FILE, index=False, sheet_name="CVE Report")
    logger.info(f"[✅ DONE] Отчет сохранен: {OUTPUT_FILE} ({len(df)} записей)")

def main():
    engine = create_engine(DB_URL)
    load_json_to_db(engine)
    export_to_excel(engine)

if __name__ == "__main__":
    main()
