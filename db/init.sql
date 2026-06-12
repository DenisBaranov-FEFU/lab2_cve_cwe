CREATE TABLE IF NOT EXISTS cve (
    id VARCHAR(30) PRIMARY KEY,
    vendor_release_date DATE,
    vendor_release_url TEXT,
    cve_url TEXT,
    published_date VARCHAR(50),
    updated_date VARCHAR(50),
    description TEXT
);

-- Таблица метрик CVSS (Связь один-ко-многим с CVE)
CREATE TABLE IF NOT EXISTS cvss (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(30) REFERENCES cve(id) ON DELETE CASCADE,
    version VARCHAR(20),
    score NUMERIC(3, 1),
    vector TEXT,
    severity VARCHAR(20)
);

-- Справочник уникальных строк CPE (Исключает транзитивные зависимости и дублирование текста)
CREATE TABLE IF NOT EXISTS cpe_dict (
    id SERIAL PRIMARY KEY,
    cpe_string TEXT UNIQUE
);

-- Таблица связей Многие-ко-Многим между CVE и CPE
CREATE TABLE IF NOT EXISTS cve_cpe (
    cve_id VARCHAR(30) REFERENCES cve(id) ON DELETE CASCADE,
    cpe_id INTEGER REFERENCES cpe_dict(id) ON DELETE CASCADE,
    PRIMARY KEY (cve_id, cpe_id)
);

-- Справочник слабых мест CWE (Атрибуты Name и Description зависят только от PK cwe_id)
CREATE TABLE IF NOT EXISTS cwe (
    id VARCHAR(30) PRIMARY KEY,
    name TEXT,
    description TEXT
);

-- Таблица связей Многие-ко-Многим между CVE и CWE
CREATE TABLE IF NOT EXISTS cve_cwe (
    cve_id VARCHAR(30) REFERENCES cve(id) ON DELETE CASCADE,
    cwe_id VARCHAR(30) REFERENCES cwe(id) ON DELETE CASCADE,
    PRIMARY KEY (cve_id, cwe_id)
);
