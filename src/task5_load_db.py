import json
import pandas as pd
from sqlalchemy import create_engine, text
import logging
import time
import os 

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

JSON_FILE = "data/result_task_2.json"

DB_HOST = os.getenv("DB_HOST", "db") 
DB_USER = os.getenv("DB_USER", "cveuser")
DB_PASS = os.getenv("DB_PASSWORD", "cvepass")
DB_NAME = os.getenv("DB_NAME", "cvedb")
DB_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:5432/{DB_NAME}"



def load_json_to_db(engine):
    logger.info(f"Загрузка данных из {JSON_FILE} в БД...")
    
    
    if not os.path.exists(JSON_FILE):
        logger.error(f"Файл {JSON_FILE} не найден!")
        return

    with open(JSON_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    
    seen_ids = set()
    unique_data = []
    for item in data:
        cve_id = item.get("ID")
        if cve_id and cve_id not in seen_ids:
            seen_ids.add(cve_id)
            unique_data.append(item)
    
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
                if not cve_id: continue
                
                
                
                
               
            except Exception as e:
                stats["errors"] += 1
                conn.rollback()
        
        conn.commit() 
        
        elapsed = time.time() - start_time
        logger.info(f"[✅ DONE] Загрузка завершена за {elapsed:.1f}с")

def main():
    engine = create_engine(DB_URL)
    load_json_to_db(engine)

if __name__ == "__main__":
    main()
