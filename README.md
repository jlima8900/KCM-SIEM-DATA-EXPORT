## Guacamole- KCM - SIEM Export Script


**Purpose:** Extracts and enriches Keeper Connection Manager (Guacamole) data into SIEM-compatible formats (JSON or CEF), supporting correlation, enrichment, and optional splitting.


##Disclaimer
⚠️ Caution: This tool modifies system configurations and handles connection data. Always test in a non-production environment first and create backups before use.

The Keeper PAM Export Tool simplifies migrating Apache Guacamole connections to Keeper's Privileged Access Management system. It automatically inspects your Docker Compose configuration, extracts database credentials, and transforms connection data into the proper format for Keeper PAM import.

This tool is not supported by Keeper and is an Individual contribution from a curious individual :)
---

## 🚀 Overview

This script enables admins and analysts to export structured log and configuration data from the KCM backend for ingestion into any SIEM. The export includes full context around connections, users, groups, permissions, and more — enriched with correlation IDs, session info, severity levels, MITRE classifications, and more.

---

## 🛠 Script Capabilities

### ✅ Supported Data Categories

| Option | Description |
|--------|-------------|
| `1`    | Connection History |
| `2`    | Users |
| `3`    | Groups |
| `4`    | Connections |
| `5`    | Connection Parameters |
| `6`    | System Permissions |
| `7`    | All of the above |
| `8`    | Connection History within a specific date range |

### ✅ Output Formats

- **JSON**: SIEM-compatible structured format with full metadata and hierarchy
- **CEF**: Common Event Format string with flattened key=value fields

---

## 🧩 Correlation and Metadata Enrichment

Each exported record includes:

| Field               | Description |
|--------------------|-------------|
| `event_id`         | Unique UUID for the record |
| `event_type`       | Describes the type (`connection_history`, `user_management`, etc.) |
| `event_source`     | Always set to `guacamole` |
| `event_source_host`| The hostname of the machine running the export |
| `event_timestamp`  | Export timestamp in ISO format |
| `correlation_id`   | Deterministic or contextual ID for linking sessions or entities |
| `event_severity`   | Logical level (`HIGH`, `MEDIUM`, `INFO`) |
| `mitre_tactic`     | If known, the MITRE ATT&CK tactic (e.g. `Lateral Movement`) |
| `mitre_technique`  | If known, the MITRE technique (e.g. `Remote Services`) |

Additional contextual blocks include:
- `source` → `{ip, user, entity_id}`
- `destination` → `{name, ip, service}`
- `identity`, `session`, `permission`, `connection_details`, `group_details`, etc.

---

## 🔍 Data Correlation Examples

### 🔁 1. Group Sessions by User (Correlate via `entity_id`)

```bash
jq '[.records[] | select(.event_type == "connection_history") | {user: .source.user, start: .session.start, duration: .session.duration_seconds}]' export.json
```

### 📌 2. Link Users to Permissions

```bash
jq '[.records[] | select(.event_type == "user_management") | {user: .identity.username, permissions: .permissions}]' export.json
```

### 🔗 3. Identify All Records With Same Correlation ID

```bash
export COR_ID="session_9aa34312"  # from any record
jq --arg id "$COR_ID" '[.records[] | select(.correlation_id == $id)]' export.json
```

### 🔒 4. Search for Redacted Connection Parameters

```bash
jq '[.records[] | select(.event_type == "connection_parameter" and .parameter.value == "[REDACTED]")]' export.json
```

---

## 📂 File Splitting

If output exceeds **10MB** or **50,000 records**, the script will:
- Split JSON into multiple `partX.json` files using `jq` range slicing
- Split CEF into multiple `.cef` parts using `split`

---

## ✅ Usage Flow

```bash
chmod +x ExportSiem.sh
./ExportSiem.sh
```

Follow interactive prompts to choose:
- Output format (JSON or CEF)
- Data category
- Optional date range (for historical data)
- Database port (default 3306)

---

## 📄 Example JSON Output

```json
{
  "event_id": "d60f4b...",
  "event_type": "connection_history",
  "event_timestamp": "2025-04-03T10:15:29Z",
  "correlation_id": "session_912aacc",
  "event_severity": "MEDIUM",
  "mitre_tactic": "Lateral Movement",
  "source": {
    "ip": "10.0.0.5",
    "user": "jdoe"
  },
  "destination": {
    "name": "internal-server",
    "ip": "10.0.0.100"
  },
  "session": {
    "start": "2025-04-03T10:00:00Z",
    "end": "2025-04-03T10:15:00Z",
    "duration_seconds": 900
  }
}
```

---

## 🧪 Validation

After export, the script:
- Validates JSON using `jq`
- Verifies file size
- Confirms number of records

---

## 🔐 Security Considerations

- Passwords and sensitive data are **hashed or redacted**
- CEF fields flatten nested structures
- Output is written to `siem_exports/` with timestamps

---

## ❓ FAQ

**Q: Can I automate this export?**  
Yes! Wrap the script in `cron` or invoke with pre-set environment variables (add CLI flag support if needed).

**Q: Why correlation IDs?**  
They help you track related events — all actions by a user, or a session lifecycle — across datasets.

**Q: Is this compliant with Splunk, QRadar, etc.?**  
Yes — outputs are compatible with standard ingestion methods. JSON is preferred for parsing-rich SIEMs; CEF works for string-based systems.

---

## 📬 Support

For help with Keeper or Guacamole integration, visit:  
➡️ https://support.keeper.io  
➡️ https://guacamole.apache.org/
