# Guacamole KCM - SIEM Export Script Documentation - Mysql/Postgres compatibble

## Purpose
Extracts and enriches Keeper Connection Manager (Guacamole) data into SIEM-compatible formats (JSON or CEF), supporting correlation, enrichment, and optional splitting.

## Disclaimer
⚠️ **Caution**: This tool modifies system configurations and handles connection data. Always test in a non-production environment first and create backups before use.

The KCM SIEM Export Tool simplifies exporting Apache Guacamole connection data to Security Information and Event Management systems. It automatically inspects your Docker Compose configuration, extracts database credentials, and transforms connection data into SIEM-compatible formats.

This tool is not officially supported by Keeper and is an individual contribution.

## Versions
Two versions are available depending on your database backend:
- `kcm-siem-mysql-export.sh` - For MySQL/MariaDB installations
- `kcm-siem-postgres-export.sh` - For PostgreSQL installations

## 🚀 Overview
This script enables admins and analysts to export structured log and configuration data from the KCM backend for ingestion into any SIEM. The export includes full context around connections, users, groups, permissions, and more — enriched with correlation IDs, session info, severity levels, MITRE classifications, and more.

## 🛠 Script Capabilities

### ✅ Supported Data Categories
| Option | Description |
|--------|-------------|
| 1 | Connection History |
| 2 | Users |
| 3 | Groups |
| 4 | Connections |
| 5 | Connection Parameters |
| 6 | System Permissions |
| 7 | All of the above |
| 8 | Connection History within a specific date range |

### ✅ Output Formats
- **JSON**: SIEM-compatible structured format with full metadata and hierarchy
- **CEF**: Common Event Format string with flattened key=value fields

### 🧩 Correlation and Metadata Enrichment
Each exported record includes:

| Field | Description |
|-------|-------------|
| event_id | Unique UUID for the record |
| event_type | Describes the type (connection_history, user_management, etc.) |
| event_source | Always set to guacamole |
| event_source_host | The hostname of the machine running the export |
| event_timestamp | Export timestamp in ISO format |
| correlation_id | Deterministic or contextual ID for linking sessions or entities |
| event_severity | Logical level (HIGH, MEDIUM, INFO) |
| mitre_tactic | If known, the MITRE ATT&CK tactic (e.g. Lateral Movement) |
| mitre_technique | If known, the MITRE technique (e.g. Remote Services) |

Additional contextual blocks include:
- `source → {ip, user, entity_id}`
- `destination → {name, ip, service}`
- `identity`, `session`, `permission`, `connection_details`, `group_details`, etc.

## 🔍 Data Correlation Examples

### 🔁 1. Group Sessions by User (Correlate via entity_id)
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

## 📂 File Splitting
If output exceeds 10MB or 50,000 records, the script will:
- Split JSON into multiple partX.json files using jq range slicing
- Split CEF into multiple .cef parts using split

## ✅ Usage Flow

```bash
# For MySQL installations
chmod +x kcm-siem-mysql-export.sh
./kcm-siem-mysql-export.sh

# For PostgreSQL installations
chmod +x kcm-siem-postgres-export.sh
./kcm-siem-postgres-export.sh
```

Follow interactive prompts to choose:
1. Output format (JSON or CEF)
2. Data category
3. Optional date range (for historical data)
4. Database port (default 3306 for MySQL, 5432 for PostgreSQL)

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

## 🧪 Validation
After export, the script:
- Validates JSON using jq
- Verifies file size
- Confirms number of records

## 🔐 Security Considerations
- Passwords and sensitive data are hashed or redacted
- CEF fields flatten nested structures
- Output is written to siem_exports/ with timestamps

## Database-Specific Features

### MySQL Version (`kcm-siem-mysql-export.sh`)
- Optimized for MySQL/MariaDB connections
- Default port: 3306
- Searches for MySQL/MariaDB environment variables in docker-compose
- Uses MySQL connectors for data extraction

### PostgreSQL Version (`kcm-siem-postgres-export.sh`)
- Optimized for PostgreSQL connections
- Default port: 5432
- Searches for PostgreSQL environment variables in docker-compose
- Uses PostgreSQL connectors for data extraction
- Enhanced container discovery for Docker-based deployments

## Guacamole Connection History Export - JSON Structure Guide

This document explains the structure and fields of the JSON export file generated by the Guacamole connection history tracking system.

### 🧩 Top-Level Structure
The root of the JSON object contains two primary keys:
- **metadata**: Contains information about the export itself.
- **records**: A list of session activity records.

### 📦 metadata Object
This section describes the context of the export:

| Key | Type | Description |
|-----|------|-------------|
| export_id | string | Unique identifier for the export batch. |
| export_timestamp | string (ISO 8601) | Time when the export was generated. |
| source_system | string | ID or name of the system producing data. |
| source_application | string | Application responsible (guacamole). |
| export_format | string | Format of the export (json). |

### 📄 records Array
Each element is an individual session history record.

#### General Fields
| Key | Type | Description |
|-----|------|-------------|
| history_id | int | Unique ID for the session history. |
| user_id | int | ID of the user initiating the connection. |
| username | string | Username in the Guacamole interface. |
| remote_host | string | Public IP of the user initiating connection. |
| connection_id | int \| null | Guacamole connection ID. |
| connection_name | string \| null | Descriptive connection name. |
| sharing_profile_id | int \| null | ID of any sharing profile used. |
| sharing_profile_name | string \| null | Name of the sharing profile. |
| start_date / end_date | string (ISO 8601) | Start and end of the session. |
| protocol | string \| null | Protocol used (rdp, ssh, etc.). |
| proxy_port / proxy_hostname | null | Possibly future proxy info. |
| entity_id | int | Source system entity ID. |
| event_id | UUID | Unique event identifier. |
| event_type | string | Always connection_history. |
| event_source | string | Typically guacamole. |
| event_source_host | int \| string | Host source ID. |
| event_timestamp | string (ISO 8601) | Event timestamp. |
| correlation_id | string | Session continuity tracking. |
| event_severity | string | Severity level (e.g., MEDIUM). |
| mitre_tactic | string | MITRE ATT&CK tactic (Lateral Movement). |
| mitre_technique | string | MITRE technique (Remote Services). |

#### Nested Structures

##### 🔁 source
Describes origin of the session:
```json
{
  "ip": "88.179.53.95",
  "user": "guacadmin",
  "entity_id": 1
}
```

##### 🎯 destination
Describes the target system:
```json
{
  "name": "KALI - RDP - root",
  "service": "rdp",
  "ip": null
}
```

##### 🔌 network (optional)
Present if a known protocol is used:
```json
{
  "protocol": "rdp",
  "application_protocol": "guacamole-rdp",
  "port": null
}
```

##### ⏱️ session
Tracks session duration:
```json
{
  "start": "2024-12-29T09:26:29",
  "end": "2024-12-29T09:27:20",
  "duration_seconds": 51.0
}
```

##### 🎬 action
Always `session_complete` for completed sessions.

### 🔍 Usage Scenarios
This structure supports:
- Auditing RDP/SSH usage.
- Tracking user access history.
- Alerting on suspicious session behavior.
- Grouping sessions by MITRE technique.
- Reporting on usage by time, user, or protocol.

## ❓ FAQ

**Q: Can I automate this export?**
Yes! Wrap the script in cron or invoke with pre-set environment variables (add CLI flag support if needed).

**Q: Why correlation IDs?**
They help you track related events — all actions by a user, or a session lifecycle — across datasets.

**Q: Is this compliant with Splunk, QRadar, etc.?**
Yes — outputs are compatible with standard ingestion methods. JSON is preferred for parsing-rich SIEMs; CEF works for string-based systems.

**Q: Which script should I use?**
Use `kcm-siem-mysql-export.sh` if your Guacamole deployment uses MySQL/MariaDB, or `kcm-siem-postgres-export.sh` if it uses PostgreSQL.

**Q: Can the scripts connect to remote databases?**
Yes, both scripts support remote database connections. You can specify the database host during the interactive prompts or via command-line parameters.

**Q: What if I encounter connection errors?**
Both scripts include robust connection testing with multiple fallback methods, including detection of Docker container IPs. If automatic connection fails, they offer guided manual credential entry.
