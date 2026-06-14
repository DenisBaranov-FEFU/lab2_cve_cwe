-- Таблица CVE
CREATE TABLE IF NOT EXISTS cves (
    id VARCHAR(255) PRIMARY KEY,
    vendor_release_date VARCHAR(255),
    vendor_release_url TEXT,
    published_date VARCHAR(255),
    description TEXT,
    score FLOAT,
    severity VARCHAR(50)
);

-- Таблица CPE
CREATE TABLE IF NOT EXISTS cpes (
    id SERIAL PRIMARY KEY,
    cpe_string TEXT UNIQUE
);

-- Таблица CWE
CREATE TABLE IF NOT EXISTS cwes (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255),
    description TEXT
);

-- Таблица связи CVE-CPE
CREATE TABLE IF NOT EXISTS cve_cpe (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(255) REFERENCES cves(id) ON DELETE CASCADE,
    cpe_id INTEGER REFERENCES cpes(id) ON DELETE CASCADE,
    UNIQUE(cve_id, cpe_id)
);

-- Таблица связи CVE-CWE
CREATE TABLE IF NOT EXISTS cve_cwe (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(255) REFERENCES cves(id) ON DELETE CASCADE,
    cwe_id VARCHAR(50) REFERENCES cwes(id) ON DELETE CASCADE,
    UNIQUE(cve_id, cwe_id)
);
