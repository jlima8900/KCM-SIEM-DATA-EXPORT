#!/bin/bash

# Function to log information messages
log_info() {
    echo -e "\033[1;32m[INFO]\033[0m $1"
}

# Function to log error messages
log_error() {
    echo -e "\033[1;31m[ERROR]\033[0m $1" >&2
}

# Function to prompt user for database port
set_database_port() {
    read -p "Enter the database port (default is 3306): " user_port
    while ! [[ "$user_port" =~ ^[0-9]+$ ]] && [[ -n "$user_port" ]]; do
        log_error "Invalid input. Please enter a numeric value."
        read -p "Enter the database port (default is 3306): " user_port
    done
    db_port=${user_port:-3306}
    log_info "Using database port: $db_port"
}

# Function to prompt user for output format
set_output_format() {
    log_info "Choose output format:"
    echo "1) JSON (SIEM Compatible)"
    echo "2) CEF (Common Event Format)"
    read -p "Enter your choice (1-2, default is 1): " format_choice
    
    case $format_choice in
        1|"") output_format="json";;
        2) output_format="cef";;
        *) log_error "Invalid choice. Using default JSON format."; output_format="json";;
    esac
    log_info "Selected output format: $output_format"
}

# Function to prompt user for data to export
menu_selection() {
    log_info "Choose what data to export:"
    echo "1) Connection History"
    echo "2) Users"
    echo "3) Groups"
    echo "4) Connections"
    echo "5) Connection Parameters"
    echo "6) System Permissions"
    echo "7) Export All"
    echo "8) Export by Date Range"
    read -p "Enter your choice (1-8): " choice

    case $choice in
        1) export_category="history";;
        2) export_category="users";;
        3) export_category="groups";;
        4) export_category="connections";;
        5) export_category="parameters";;
        6) export_category="permissions";;
        7) export_category="all";;
        8) export_category="date_range"; set_date_range;;
        *) log_error "Invalid choice. Please enter a number between 1-8."; exit 1;;
    esac
    log_info "Selected export category: $export_category"
}

# Function to set date range
set_date_range() {
    read -p "Enter start date (YYYY-MM-DD): " start_date
    read -p "Enter end date (YYYY-MM-DD, leave empty for today): " end_date
    
    # Validate date format
    if ! [[ "$start_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        log_error "Invalid start date format. Please use YYYY-MM-DD."
        exit 1
    fi
    
    if [[ -z "$end_date" ]]; then
        end_date=$(date +%Y-%m-%d)
    elif ! [[ "$end_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        log_error "Invalid end date format. Please use YYYY-MM-DD."
        exit 1
    fi
    
    log_info "Date range: $start_date to $end_date"
}

# Function to extract database credentials using Python
extract_db_credentials() {
    log_info "Extracting database credentials from docker-compose.yml..."
    credentials=$(python3 - <<EOF
import yaml, json
docker_compose_file = '/etc/kcm-setup/docker-compose.yml'
try:
    with open(docker_compose_file, 'r') as file:
        compose_data = yaml.safe_load(file)
        db_service = compose_data['services']['db']
        environment = db_service['environment']
        db_name = environment.get('GUACAMOLE_DATABASE', 'guacamole_db')
        db_user = environment.get('GUACAMOLE_USERNAME', 'guacamole_user')
        db_password = environment.get('GUACAMOLE_PASSWORD', 'password')
        print(json.dumps({"user": db_user, "password": db_password, "database": db_name}))
except Exception as e:
    print(json.dumps({"error": str(e)}))
    exit(1)
EOF
)
    error=$(echo "$credentials" | jq -r '.error // empty')
    if [[ -n "$error" ]]; then
        log_error "Failed to extract credentials: $error"
        exit 1
    fi
    db_user=$(echo "$credentials" | jq -r '.user')
    db_password=$(echo "$credentials" | jq -r '.password')
    database=$(echo "$credentials" | jq -r '.database')
    log_info "Database credentials extracted successfully."
}

# Function to export data using Python
export_data() {
    timestamp=$(date +%Y%m%d_%H%M%S)
    export_dir="${PWD}/siem_exports"
    mkdir -p "$export_dir"
    
    if [[ "$output_format" == "json" ]]; then
        export_file="${export_dir}/export_data_${timestamp}.json"
    else
        export_file="${export_dir}/export_data_${timestamp}.cef"
    fi
    
    if ! touch "$export_file" 2>/dev/null; then
        log_error "Cannot write to export file location: $export_file"
        exit 1
    fi
    
    log_info "Exporting data to $export_file..."
    
    python3 - <<EOF
import mysql.connector
import json
import sys
import uuid
import socket
import hashlib
from datetime import datetime

db_config = {
    "host": "localhost",
    "port": ${db_port},
    "user": "${db_user}",
    "password": "${db_password}",
    "database": "${database}"
}

def serialize(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)

def generate_correlation_id(record, event_type):
    """Generate a consistent correlation ID based on record data"""
    if event_type == "connection_history":
        # Use history ID for correlation
        return f"session_{record.get('history_id', '')}"
    elif "entity_id" in record:
        # Use entity ID for user events
        return f"user_{record.get('entity_id', '')}_event"
    elif "connection_id" in record:
        # Use connection ID for connection events
        return f"connection_{record.get('connection_id', '')}_event"
    else:
        # Default to a random ID
        return f"{event_type}_{uuid.uuid4().hex[:8]}"

def hash_sensitive_data(data):
    """Hash sensitive data for security"""
    if data is None:
        return None
    hash_obj = hashlib.sha256(str(data).encode())
    return hash_obj.hexdigest()

def add_siem_metadata(record, event_type):
    """Add SIEM-compatible metadata to record"""
    # Add standard SIEM fields
    record["event_id"] = str(uuid.uuid4())
    record["event_type"] = event_type
    record["event_source"] = "guacamole"
    record["event_source_host"] = socket.gethostname()
    record["event_timestamp"] = datetime.now().isoformat()
    record["correlation_id"] = generate_correlation_id(record, event_type)
    
    # Add severity
    if event_type in ["system_permission", "user_permission"]:
        record["event_severity"] = "HIGH"
    elif event_type == "connection_history":
        record["event_severity"] = "MEDIUM"
    else:
        record["event_severity"] = "INFO"
    
    # Add MITRE ATT&CK classification where applicable
    if event_type == "connection_history":
        record["mitre_tactic"] = "Lateral Movement"
        record["mitre_technique"] = "Remote Services"
    elif event_type == "system_permission":
        record["mitre_tactic"] = "Privilege Escalation"
        record["mitre_technique"] = "Valid Accounts"
    
    return record

# Helper function for permission descriptions
def get_permission_description(permission):
    """Get human-readable description for system permissions"""
    descriptions = {
        'CREATE_CONNECTION': 'Create Connections',
        'CREATE_CONNECTION_GROUP': 'Create Connection Groups',
        'CREATE_SHARING_PROFILE': 'Create Sharing Profiles',
        'CREATE_USER': 'Create Users',
        'CREATE_USER_GROUP': 'Create User Groups',
        'ADMINISTER': 'System Administration'
    }
    return descriptions.get(permission, permission)

try:
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    
    data = {"metadata": {
        "export_id": str(uuid.uuid4()),
        "export_timestamp": datetime.now().isoformat(),
        "source_system": socket.gethostname(),
        "source_application": "guacamole",
        "export_format": "${output_format}"
    }, "records": []}
    
    cef_output = []
    
    # Connection History with enhanced context
    if "${export_category}" in ["history", "all", "date_range"]:
        try:
            query = """
                SELECT 
                    ch.*, 
                    c.protocol, 
                    c.connection_name,
                    c.proxy_port, 
                    c.proxy_hostname,
                    u.entity_id,
                    e.name as username
                FROM guacamole_connection_history ch
                LEFT JOIN guacamole_connection c ON ch.connection_id = c.connection_id
                LEFT JOIN guacamole_user u ON ch.user_id = u.user_id
                LEFT JOIN guacamole_entity e ON u.entity_id = e.entity_id
            """
            
            # Add date range filter if specified
            if "${export_category}" == "date_range":
                query += " WHERE ch.start_date BETWEEN '${start_date} 00:00:00' AND '${end_date} 23:59:59'"
                
            cursor.execute(query)
            records = cursor.fetchall()
            print(f"[INFO] Found {len(records)} connection history records")
            
            for record in records:
                # Create enhanced SIEM record
                siem_record = add_siem_metadata(record, "connection_history")
                
                # Add network context
                if record.get("protocol"):
                    siem_record["network"] = {
                        "protocol": record["protocol"].lower(),
                        "application_protocol": f"guacamole-{record['protocol'].lower()}",
                        "port": record.get("proxy_port")
                    }
                
                # Add source/destination context
                siem_record["source"] = {
                    "ip": record.get("remote_host"),
                    "user": record.get("username", record.get("entity_id")),
                    "entity_id": record.get("entity_id")
                }
                
                siem_record["destination"] = {
                    "name": record.get("connection_name"),
                    "service": record.get("protocol"),
                    "ip": record.get("proxy_hostname")
                }
                
                # Add session context
                if record.get("start_date") and record.get("end_date"):
                    start = record["start_date"]
                    end = record["end_date"]
                    if isinstance(start, datetime) and isinstance(end, datetime):
                        duration = (end - start).total_seconds()
                        siem_record["session"] = {
                            "start": serialize(start),
                            "end": serialize(end),
                            "duration_seconds": duration
                        }
                        siem_record["action"] = "session_complete"
                    else:
                        siem_record["action"] = "session_unknown"
                elif record.get("start_date") and not record.get("end_date"):
                    siem_record["session"] = {
                        "start": serialize(record["start_date"])
                    }
                    siem_record["action"] = "session_start"
                
                if "${output_format}" == "json":
                    data["records"].append(siem_record)
                else:
                    # Format as CEF
                    cef_header = f"CEF:0|Guacamole|AccessGateway|1.0|connection_history|Guacamole Connection|5|"
                    extensions = []
                    for k, v in siem_record.items():
                        if v is not None and not isinstance(v, dict):
                            extensions.append(f"{k}={v}")
                    # Add nested fields flattened
                    if "network" in siem_record:
                        for nk, nv in siem_record["network"].items():
                            if nv is not None:
                                extensions.append(f"network.{nk}={nv}")
                    if "source" in siem_record:
                        for sk, sv in siem_record["source"].items():
                            if sv is not None:
                                extensions.append(f"src.{sk}={sv}")
                    if "destination" in siem_record:
                        for dk, dv in siem_record["destination"].items():
                            if dv is not None:
                                extensions.append(f"dst.{dk}={dv}")
                    if "session" in siem_record:
                        for sk, sv in siem_record["session"].items():
                            if sv is not None:
                                extensions.append(f"session.{sk}={sv}")
                    
                    cef_output.append(cef_header + " ".join(extensions))
        except Exception as e:
            print(f"[ERROR] Error processing connection history: {e}")

    # Users with enhanced context
    if "${export_category}" in ["users", "all"]:
        try:
            query = """
                SELECT 
                    u.*,
                    e.name as username
                FROM guacamole_user u
                LEFT JOIN guacamole_entity e ON u.entity_id = e.entity_id
            """
            cursor.execute(query)
            records = cursor.fetchall()
            print(f"[INFO] Found {len(records)} user records")
            
            for record in records:
                # Secure sensitive data
                if "password" in record:
                    record["password_hash"] = hash_sensitive_data(record["password"])
                    del record["password"]
                if "password_salt" in record:
                    record["password_salt_hash"] = hash_sensitive_data(record["password_salt"])
                    del record["password_salt"]
                    
                # Add SIEM metadata
                siem_record = add_siem_metadata(record, "user_management")
                
                # Add identity context
                siem_record["identity"] = {
                    "entity_id": record.get("entity_id"),
                    "username": record.get("username", ""),
                    "creation_date": serialize(record.get("creation_date")),
                    "last_password_change": serialize(record.get("last_password_change"))
                }
                
                # Attempt to get user permissions - using entity_id instead of user_id
                try:
                    if record.get("entity_id"):
                        cursor.execute(f"""
                            SELECT permission 
                            FROM guacamole_user_permission 
                            WHERE affected_user_id = '{record.get("entity_id")}'
                        """)
                        permissions = cursor.fetchall()
                        if permissions:
                            siem_record["permissions"] = [p.get("permission") for p in permissions if p.get("permission")]
                except Exception as e:
                    print(f"[WARNING] Could not retrieve permissions for entity {record.get('entity_id')}: {e}")
                
                if "${output_format}" == "json":
                    data["records"].append(siem_record)
                else:
                    # Format as CEF
                    cef_header = f"CEF:0|Guacamole|AccessGateway|1.0|user_management|Guacamole User|5|"
                    extensions = []
                    for k, v in siem_record.items():
                        if v is not None and not isinstance(v, dict) and not isinstance(v, list):
                            extensions.append(f"{k}={v}")
                    # Add nested fields flattened
                    if "identity" in siem_record:
                        for ik, iv in siem_record["identity"].items():
                            if iv is not None:
                                extensions.append(f"identity.{ik}={iv}")
                    if "permissions" in siem_record:
                        permissions_str = ",".join(siem_record["permissions"])
                        extensions.append(f"permissions={permissions_str}")
                    
                    cef_output.append(cef_header + " ".join(extensions))
        except Exception as e:
            print(f"[ERROR] Error processing users: {e}")

    # Connection Groups
    if "${export_category}" in ["groups", "all"]:
        try:
            cursor.execute("SELECT * FROM guacamole_connection_group")
            records = cursor.fetchall()
            print(f"[INFO] Found {len(records)} connection group records")
            
            for record in records:
                siem_record = add_siem_metadata(record, "connection_group")
                
                # Add group context
                siem_record["group_details"] = {
                    "group_id": record.get("connection_group_id"),
                    "name": record.get("connection_group_name"),
                    "type": record.get("type"),
                    "parent_id": record.get("parent_id")
                }
                
                if "${output_format}" == "json":
                    data["records"].append(siem_record)
                else:
                    # Format as CEF
                    cef_header = f"CEF:0|Guacamole|AccessGateway|1.0|connection_group|Guacamole Group|5|"
                    extensions = []
                    for k, v in siem_record.items():
                        if v is not None and not isinstance(v, dict):
                            extensions.append(f"{k}={v}")
                    if "group_details" in siem_record:
                        for gk, gv in siem_record["group_details"].items():
                            if gv is not None:
                                extensions.append(f"group.{gk}={gv}")
                    
                    cef_output.append(cef_header + " ".join(extensions))
        except Exception as e:
            print(f"[ERROR] Error processing connection groups: {e}")

    # Connections with enhanced protocol information
    if "${export_category}" in ["connections", "all"]:
        try:
            cursor.execute("""
                SELECT c.*, cg.connection_group_name as parent_group_name
                FROM guacamole_connection c
                LEFT JOIN guacamole_connection_group cg ON c.parent_id = cg.connection_group_id
            """)
            records = cursor.fetchall()
            print(f"[INFO] Found {len(records)} connection records")
            
            for record in records:
                siem_record = add_siem_metadata(record, "connection_config")
                
                # Add connection details
                siem_record["connection_details"] = {
                    "connection_id": record.get("connection_id"),
                    "name": record.get("connection_name"),
                    "protocol": record.get("protocol"),
                    "parent_group": record.get("parent_group_name"),
                    "proxy_hostname": record.get("proxy_hostname"),
                    "proxy_port": record.get("proxy_port"),
                    "max_connections": record.get("max_connections"),
                    "max_connections_per_user": record.get("max_connections_per_user")
                }
                
                # Add parameters (through a subquery)
                try:
                    cursor.execute(f"""
                        SELECT parameter_name, parameter_value
                        FROM guacamole_connection_parameter
                        WHERE connection_id = {record['connection_id']}
                    """)
                    parameters = cursor.fetchall()
                    
                    connection_params = {}
                    sensitive_params = ['password', 'private-key', 'passphrase', 'key-passphrase']
                    
                    for param in parameters:
                        name = param.get("parameter_name")
                        value = param.get("parameter_value")
                        
                        # Redact sensitive parameters
                        if name in sensitive_params:
                            connection_params[name] = "[REDACTED]"
                        else:
                            connection_params[name] = value
                    
                    if connection_params:
                        siem_record["connection_parameters"] = connection_params
                except Exception as e:
                    print(f"[WARNING] Could not retrieve parameters for connection {record.get('connection_id')}: {e}")
                
                if "${output_format}" == "json":
                    data["records"].append(siem_record)
                else:
                    # Format as CEF
                    cef_header = f"CEF:0|Guacamole|AccessGateway|1.0|connection_config|Guacamole Connection|5|"
                    extensions = []
                    for k, v in siem_record.items():
                        if v is not None and not isinstance(v, dict):
                            extensions.append(f"{k}={v}")
                    if "connection_details" in siem_record:
                        for ck, cv in siem_record["connection_details"].items():
                            if cv is not None:
                                extensions.append(f"conn.{ck}={cv}")
                    if "connection_parameters" in siem_record:
                        for pk, pv in siem_record["connection_parameters"].items():
                            if pv is not None:
                                extensions.append(f"param.{pk}={pv}")
                    
                    cef_output.append(cef_header + " ".join(extensions))
        except Exception as e:
            print(f"[ERROR] Error processing connections: {e}")

    # Connection Parameters with sensitive data protection
    if "${export_category}" in ["parameters", "all"]:
        try:
            cursor.execute("""
                SELECT cp.*, c.connection_name, c.protocol
                FROM guacamole_connection_parameter cp
                JOIN guacamole_connection c ON cp.connection_id = c.connection_id
            """)
            records = cursor.fetchall()
            print(f"[INFO] Found {len(records)} connection parameter records")
            
            for record in records:
                # Redact sensitive parameters
                sensitive_params = ['password', 'private-key', 'passphrase', 'key-passphrase']
                if record.get('parameter_name') in sensitive_params:
                    record['parameter_value'] = '[REDACTED]'
                
                siem_record = add_siem_metadata(record, "connection_parameter")
                
                # Add parameter context
                siem_record["parameter"] = {
                    "connection_id": record.get("connection_id"),
                    "connection_name": record.get("connection_name"),
                    "protocol": record.get("protocol"),
                    "name": record.get("parameter_name"),
                    "value": record.get("parameter_value")
                }
                
                if "${output_format}" == "json":
                    data["records"].append(siem_record)
                else:
                    # Format as CEF
                    cef_header = f"CEF:0|Guacamole|AccessGateway|1.0|connection_parameter|Guacamole Parameter|5|"
                    extensions = []
                    for k, v in siem_record.items():
                        if v is not None and not isinstance(v, dict):
                            extensions.append(f"{k}={v}")
                    if "parameter" in siem_record:
                        for pk, pv in siem_record["parameter"].items():
                            if pv is not None:
                                extensions.append(f"param.{pk}={pv}")
                    
                    cef_output.append(cef_header + " ".join(extensions))
        except Exception as e:
            print(f"[ERROR] Error processing connection parameters: {e}")

    # System Permissions with entity context to match your schema
    if "${export_category}" in ["permissions", "all"]:
        try:
            cursor.execute("""
                SELECT sp.*, e.name as username
                FROM guacamole_system_permission sp
                JOIN guacamole_entity e ON sp.entity_id = e.entity_id
            """)
            records = cursor.fetchall()
            print(f"[INFO] Found {len(records)} system permission records")
            
            for record in records:
                siem_record = add_siem_metadata(record, "system_permission")
                
                # Add permission context
                siem_record["permission"] = {
                    "entity_id": record.get("entity_id"),
                    "username": record.get("username"),
                    "permission": record.get("permission"),
                    "permission_description": get_permission_description(record.get("permission"))
                }
                
                if "${output_format}" == "json":
                    data["records"].append(siem_record)
                else:
                    # Format as CEF
                    cef_header = f"CEF:0|Guacamole|AccessGateway|1.0|system_permission|Guacamole Permission|5|"
                    extensions = []
                    for k, v in siem_record.items():
                        if v is not None and not isinstance(v, dict):
                            extensions.append(f"{k}={v}")
                    if "permission" in siem_record:
                        for pk, pv in siem_record["permission"].items():
                            if pv is not None:
                                extensions.append(f"perm.{pk}={pv}")
                    
                    cef_output.append(cef_header + " ".join(extensions))
        except Exception as e:
            print(f"[ERROR] Error processing system permissions: {e}")

    # Output the data in the selected format
    if "${output_format}" == "json":
        with open("${export_file}", "w") as file:
            json.dump(data, file, indent=4, default=serialize)
        print(f"[INFO] Exported {len(data['records'])} records to JSON format")
    else:
        with open("${export_file}", "w") as file:
            for line in cef_output:
                file.write(line + "\\n")
        print(f"[INFO] Exported {len(cef_output)} records to CEF format")
            
    print("[INFO] Data export completed successfully!")

except mysql.connector.Error as err:
    print(f"[ERROR] Database error: {err}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"[ERROR] An unexpected error occurred: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc()
    sys.exit(1)
finally:
    if 'cursor' in locals() and cursor:
        cursor.close()
    if 'conn' in locals() and conn.is_connected():
        conn.close()
EOF
}

# Function to verify export
verify_export() {
    log_info "Verifying export file..."
    
    if [[ ! -f "$export_file" ]]; then
        log_error "Export file not found: $export_file"
        return 1
    fi
    
    file_size=$(stat -c %s "$export_file")
    if [[ "$file_size" -lt 100 ]]; then
        log_error "Export file is too small: $file_size bytes"
        return 1
    fi
    
    if [[ "$output_format" == "json" ]]; then
        if ! jq empty "$export_file" 2>/dev/null; then
            log_error "Invalid JSON format in export file"
            return 1
        fi
        
        record_count=$(jq '.records | length' "$export_file")
        log_info "Successfully exported $record_count records"
    else
        record_count=$(wc -l < "$export_file")
        log_info "Successfully exported $record_count CEF records"
    fi
    
    return 0
}

# Function to split large files
split_large_files() {
    log_info "Checking if file needs to be split..."
    
    # Set threshold to 10MB or 50,000 records
    size_threshold=$((10 * 1024 * 1024))  # 10MB in bytes
    record_threshold=50000
    
    file_size=$(stat -c %s "$export_file")
    
    if [[ "$output_format" == "json" ]]; then
        record_count=$(jq '.records | length' "$export_file")
        
        if [[ "$file_size" -gt "$size_threshold" || "$record_count" -gt "$record_threshold" ]]; then
            log_info "File is large ($file_size bytes, $record_count records). Splitting..."
            
            # Extract base name without extension
            base_name="${export_file%.json}"
            
            # Calculate number of chunks
            chunk_count=$(( (record_count + record_threshold - 1) / record_threshold ))
            log_info "Splitting into $chunk_count chunks..."
            
            # Use jq to split the file
            for (( i=0; i<chunk_count; i++ )); do
                start=$(( i * record_threshold ))
                chunk_file="${base_name}_part$((i+1)).json"
                
                jq --argjson start "$start" --argjson limit "$record_threshold" \
                   '{ metadata: .metadata, records: .records[$start:($start+$limit)] }' \
                   "$export_file" > "$chunk_file"
                   
                chunk_record_count=$(jq '.records | length' "$chunk_file")
                log_info "Created $chunk_file with $chunk_record_count records"
            done
            
            log_info "Original file preserved at $export_file"
        else
            log_info "File is below threshold, no splitting needed"
        fi
    else
        # For CEF, split by line count
        if [[ "$file_size" -gt "$size_threshold" ]]; then
            log_info "File is large ($file_size bytes). Splitting..."
            
            # Extract base name without extension
            base_name="${export_file%.cef}"
            
            # Split file
            split -l "$record_threshold" --numeric-suffixes=1 --suffix-length=1 \
                  "$export_file" "${base_name}_part"
                  
            # Rename files with proper extension
            for part in "${base_name}_part"*; do
                mv "$part" "${part}.cef"
                record_count=$(wc -l < "${part}.cef")
                log_info "Created ${part}.cef with $record_count records"
            done
            
            log_info "Original file preserved at $export_file"
        else
            log_info "File is below threshold, no splitting needed"
        fi
    fi
}

# Main script execution
log_info "Starting SIEM-compatible export script..."
set_database_port
set_output_format
extract_db_credentials
menu_selection
export_data
verify_export
split_large_files
log_info "Script execution completed successfully."
