import json
from jsonschema import validate, ValidationError

DATA_FILE = "data/result_task_2.json"
SCHEMA_FILE = "data/json_schema.json"

SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "array",
    "minItems": 1,
    "items": {
        "type": "object",
        "required": [
            "ID", "vendor_release_date", "vendor_release_url", "url",
            "published_date", "updated_date", "description",
            "cvss_list", "cpe_list", "cwe"
        ],
        "properties": {
            "ID": {"type": "string", "pattern": "^CVE-[0-9]{4}-[0-9]{4,7}$"},
            "vendor_release_date": {"type": "string", "minLength": 1},
            "vendor_release_url": {"type": "string", "minLength": 1},
            "url": {"type": "string", "minLength": 1},
            "published_date": {"type": "string", "minLength": 1},
            "updated_date": {"type": "string", "minLength": 1},
            "description": {"type": "string", "minLength": 1},
            "cvss_list": {
                "type": "array", "minItems": 1,
                "items": {
                    "type": "object",
                    "required": ["version", "score", "vector", "severity"],
                    "properties": {
                        "version": {"type": "string", "minLength": 1},
                        "score": {"type": ["number", "integer", "null"]},
                        "vector": {"type": "string", "minLength": 1},
                        "severity": {"type": "string", "minLength": 1}
                    }
                }
            },
            "cpe_list": {
                "type": "array", "minItems": 1,
                "items": {"type": "string", "minLength": 1}
            },
            "cwe": {
                "type": "object", "minProperties": 1,
                "additionalProperties": {
                    "type": "object",
                    "required": ["name", "description"],
                    "properties": {
                        "name": {"type": "string", "minLength": 1},
                        "description": {"type": "string", "minLength": 1}
                    }
                }
            }
        }
    }
}

def main():
    
    with open(SCHEMA_FILE, "w", encoding="utf-8") as f:
        json.dump(SCHEMA, f, ensure_ascii=False, indent=2)

    
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    print(f"[INFO] Начинаю валидацию {len(data)} записей...")
    
    invalid_cves = []
    
    
    for idx, item in enumerate(data):
        try:
            validate(instance=item, schema=SCHEMA["items"])
        except ValidationError as e:
            cve_id = item.get("ID", "UNKNOWN_ID")
            invalid_cves.append((cve_id, e.message))

    
    if not invalid_cves:
        print("[✅ DONE] Validation passed successfully! Все записи корректны.")
    else:
        print(f"[❌ ERROR] Найдено невалидных записей: {len(invalid_cves)} из {len(data)}")
        print("[INFO] Проблемные CVE и причины:")
        for cve_id, error_msg in invalid_cves[:5]: 
            print(f"  - {cve_id}: {error_msg}")
        
        print("\n[INFO] Если данные отсутствуют, то вписываются заглушки 'N/A'.")

if __name__ == "__main__":
    main()
