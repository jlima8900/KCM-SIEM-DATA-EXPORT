#!/bin/bash

# Function to log messages with different levels
log_info() {
    echo -e "\033[1;32m[INFO]\033[0m $1"
}

log_error() {
    echo -e "\033[1;31m[ERROR]\033[0m $1" >&2
}

log_warn() {
    echo -e "\033[1;33m[WARNING]\033[0m $1" >&2
}

log_success() {
    echo -e "\033[1;32m[SUCCESS]\033[0m $1"
}

log_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "\033[1;36m[DEBUG]\033[0m $1" >&2
    fi
}

# Variables
DB_HOST="localhost"
DB_PORT="5432"
db_user=""
db_password=""
database=""
ADMIN_PASS=""
DB_SERVICE="db"
COMPOSE_FILE="/etc/kcm-setup/docker-compose.yml"
DEBUG=false
CONNECTION_VERIFIED=false

# Function to prompt user for database port
set_database_port() {
    read -p "Enter the database port (default is 5432): " user_port
    while ! [[ "$user_port" =~ ^[0-9]+$ ]] && [[ -n "$user_port" ]]; do
        log_error "Invalid input. Please enter a numeric value."
        read -p "Enter the database port (default is 5432): " user_port
    done
    DB_PORT=${user_port:-5432}
    log_info "Using database port: $DB_PORT"
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
    log_info "Extracting PostgreSQL credentials from docker-compose.yml..."

    COMPOSE_FILE="${COMPOSE_FILE:-/etc/kcm-setup/docker-compose.yml}"
    DB_SERVICE="${DB_SERVICE:-db}"

    if [[ -z "$DB_SERVICE" ]]; then
        log_error "Database service name not available. Run inspect_compose_file first."
        exit 1
    fi

    # Enhanced credential extraction specifically focused on PostgreSQL credentials
    credentials=$(python3 - <<EOF
import yaml, json
try:
    compose_file = "$COMPOSE_FILE"
    db_service = "$DB_SERVICE"

    with open(compose_file) as file:
        config = yaml.safe_load(file)

        if 'services' not in config or db_service not in config['services']:
            print(json.dumps({
                "status": "error",
                "message": f"Service '{db_service}' not found in compose file"
            }))
            exit(0)

        service_config = config['services'][db_service]
        env_vars = {}

        # Extract environment variables
        if 'environment' in service_config:
            env = service_config['environment']

            # Handle dict format
            if isinstance(env, dict):
                env_vars = env
            # Handle list format like ["KEY=VALUE"]
            elif isinstance(env, list):
                for item in env:
                    if isinstance(item, str) and '=' in item:
                        key, value = item.split('=', 1)
                        env_vars[key] = value

        # Look specifically for Guacamole PostgreSQL database credentials
        username = None
        password = None
        database = None
        admin_password = None

        # First priority: Look for Guacamole-specific credentials
        if 'GUACAMOLE_USERNAME' in env_vars:
            username = env_vars['GUACAMOLE_USERNAME']
        elif 'GUACAMOLE_USER' in env_vars:
            username = env_vars['GUACAMOLE_USER']
            
        if 'GUACAMOLE_PASSWORD' in env_vars:
            password = env_vars['GUACAMOLE_PASSWORD']
            
        if 'GUACAMOLE_DATABASE' in env_vars:
            database = env_vars['GUACAMOLE_DATABASE']
        
        # Store admin password if available
        if 'GUACAMOLE_ADMIN_PASSWORD' in env_vars:
            admin_password = env_vars['GUACAMOLE_ADMIN_PASSWORD']

        # Second priority: Look for standard PostgreSQL credentials if Guacamole-specific ones not found
        if not username:
            if 'POSTGRES_USER' in env_vars:
                username = env_vars['POSTGRES_USER']
            elif 'POSTGRESQL_USER' in env_vars:
                username = env_vars['POSTGRESQL_USER']
            elif 'PGUSER' in env_vars:
                username = env_vars['PGUSER']
            else:
                username = "postgres"  # Default PostgreSQL user
        
        if not password and 'POSTGRES_PASSWORD' in env_vars:
            password = env_vars['POSTGRES_PASSWORD']
        elif not password and 'POSTGRESQL_PASSWORD' in env_vars:
            password = env_vars['POSTGRESQL_PASSWORD']
        elif not password and 'PGPASSWORD' in env_vars:
            password = env_vars['PGPASSWORD']
            
        if not database:
            if 'POSTGRES_DB' in env_vars:
                database = env_vars['POSTGRES_DB']
            elif 'POSTGRESQL_DB' in env_vars:
                database = env_vars['POSTGRESQL_DB']
            elif 'PGDATABASE' in env_vars:
                database = env_vars['PGDATABASE']
        
        # If still no database, use these defaults in order
        if not database:
            for default_db in ['guacamole_db', 'guacamole', 'postgres']:
                database = default_db
                break

        # Prepare result
        result = {
            "status": "success",
            "user": username,
            "password": password,
            "database": database,
            "admin_password": admin_password
        }

        # Flag if credentials seem incomplete
        if not username or not password:
            result["status"] = "incomplete"
            result["message"] = "Some PostgreSQL credentials could not be extracted automatically"

        print(json.dumps(result))
except Exception as e:
    print(json.dumps({
        "status": "error",
        "message": str(e)
    }))
EOF
)

    # For security, redact passwords in debug output
    if [[ "${DEBUG:-false}" == "true" ]]; then
        redacted_credentials=$(echo "$credentials" | jq '.password = "REDACTED" | .admin_password = "REDACTED"')
        log_debug "Credential extraction result: $redacted_credentials"
    fi

    status=$(echo "$credentials" | jq -r '.status')

    if [[ "$status" == "error" ]]; then
        message=$(echo "$credentials" | jq -r '.message')
        log_error "Failed to extract credentials: $message"
        prompt_manual_credentials
    elif [[ "$status" == "incomplete" ]]; then
        message=$(echo "$credentials" | jq -r '.message')
        log_warn "$message"

        # Try to use partial credentials if available
        db_user=$(echo "$credentials" | jq -r '.user // empty')
        db_password=$(echo "$credentials" | jq -r '.password // empty')
        database=$(echo "$credentials" | jq -r '.database // empty')

        # Store admin password for fallback connection attempts
        ADMIN_PASS=$(echo "$credentials" | jq -r '.admin_password // empty')

        log_info "Some credentials were extracted. You may need to provide missing details."
        if [[ -z "$db_user" || -z "$db_password" || -z "$database" ]]; then
            prompt_manual_credentials
        fi
    else
        db_user=$(echo "$credentials" | jq -r '.user')
        db_password=$(echo "$credentials" | jq -r '.password')
        database=$(echo "$credentials" | jq -r '.database')
        ADMIN_PASS=$(echo "$credentials" | jq -r '.admin_password // empty')

        log_success "PostgreSQL credentials extracted successfully."
        log_info "Username: $db_user, Database: $database"
        
        if [[ -n "$ADMIN_PASS" ]]; then
            log_debug "Guacamole admin password found (will be used for fallback authentication if needed)"
        fi
    fi
}

# Helper function to prompt for manual credentials input
prompt_manual_credentials() {
    log_info "Please enter database connection details manually:"

    # Prefill with any values we already have
    [[ -n "$db_user" ]] && default_user="[$db_user]" || default_user=""
    [[ -n "$database" ]] && default_db="[$database]" || default_db=""

    read -p "Database username ${default_user}: " input_user
    read -sp "Database password: " input_pass
    echo ""
    read -p "Database name ${default_db}: " input_db

    # Only update if input is provided
    [[ -n "$input_user" ]] && db_user="$input_user"
    [[ -n "$input_pass" ]] && db_password="$input_pass"
    [[ -n "$input_db" ]] && database="$input_db"

    # Validate the entered credentials
    if [[ -z "$db_user" || -z "$db_password" || -z "$database" ]]; then
        log_error "All database connection fields are required"
        exit 1
    fi

    log_info "Manual connection details accepted"
}

# Function to verify database connection
verify_db_connection() {
    log_info "Verifying PostgreSQL connection..."

    CONNECTION_VERIFIED=false
    MAX_RETRIES=3

    # Try multiple connection approaches in sequence
    # Approach 1: Try with extracted credentials
    log_info "Connection attempt #1: Using extracted credentials on $DB_HOST:$DB_PORT"
    if test_postgres_connection "$DB_HOST" "$DB_PORT" "$db_user" "$db_password" "$database"; then
        CONNECTION_VERIFIED=true
        log_success "PostgreSQL connection successful with extracted credentials"
        return 0
    fi

    # Approach 2: Try with container name as host
    if [[ "$DB_HOST" == "localhost" && -n "$DB_SERVICE" ]]; then
        log_info "Connection attempt #2: Using container name as host"
        if test_postgres_connection "$DB_SERVICE" "$DB_PORT" "$db_user" "$db_password" "$database"; then
            CONNECTION_VERIFIED=true
            DB_HOST="$DB_SERVICE"
            log_success "PostgreSQL connection successful using container name as host"
            return 0
        fi
    fi

    # Approach 3: Try with guacamole admin credentials if available
    if [[ -n "$ADMIN_PASS" ]]; then
        log_info "Connection attempt #3: Using Guacamole admin credentials"
        if test_postgres_connection "$DB_HOST" "$DB_PORT" "$db_user" "$ADMIN_PASS" "$database"; then
            CONNECTION_VERIFIED=true
            db_password="$ADMIN_PASS"
            log_success "PostgreSQL connection successful using Guacamole admin credentials"
            return 0
        fi
    fi
    
    # Approach 4: Try with postgres superuser
    log_info "Connection attempt #4: Using postgres superuser"
    if test_postgres_connection "$DB_HOST" "$DB_PORT" "postgres" "$db_password" "$database"; then
        CONNECTION_VERIFIED=true
        db_user="postgres"
        log_success "PostgreSQL connection successful with postgres superuser"
        return 0
    fi

    # Approach 5: Try common database names if the specified one failed
    log_info "Connection attempt #5: Trying alternative PostgreSQL database names"
    for alt_db in "guacamole" "guacamole_db" "postgres" "public"; do
        if [[ "$alt_db" != "$database" ]]; then
            log_info "Trying database name: $alt_db"
            if test_postgres_connection "$DB_HOST" "$DB_PORT" "$db_user" "$db_password" "$alt_db"; then
                CONNECTION_VERIFIED=true
                database="$alt_db"
                log_success "PostgreSQL connection successful with database: $database"
                return 0
            fi
        fi
    done

    # Compare scripts for differences
    log_info "Let's compare connection parameters with the other working script:"
    log_info "- This script is trying to connect to: ${DB_HOST}:${DB_PORT} with user ${db_user}"
    log_info "- If this doesn't match your working script, consider using those exact parameters"
    log_info "- Alternatively, we can try to detect Docker network settings..."

    # Try to get Docker container IP as an alternative connection method
    if command -v docker &>/dev/null; then
        if [[ -n "$DB_SERVICE" ]]; then
            log_info "Attempting to find Docker container IP for service: $DB_SERVICE"
            container_id=$(docker ps --filter "name=$DB_SERVICE" --format "{{.ID}}" | head -1)
            
            if [[ -n "$container_id" ]]; then
                container_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container_id")
                if [[ -n "$container_ip" ]]; then
                    log_info "Found container IP: $container_ip - will try this as alternative host"
                    
                    # Try connecting using container IP
                    log_info "Connection attempt using Docker container IP: $container_ip:$DB_PORT"
                    if test_postgres_connection "$container_ip" "$DB_PORT" "$db_user" "$db_password" "$database"; then
                        CONNECTION_VERIFIED=true
                        DB_HOST="$container_ip"
                        log_success "PostgreSQL connection successful using container IP!"
                        return 0
                    fi
                fi
            fi
        fi
    fi

    # If all automatic attempts fail, prompt for manual credentials
    log_warn "All automatic PostgreSQL connection attempts failed."
    log_info "Would you like to enter different PostgreSQL credentials?"
    read -p "Try different credentials? [Y/n]: " try_different

    if [[ -z "$try_different" || "$try_different" =~ ^[Yy]$ ]]; then
        prompt_manual_credentials

        # Try with the new manual credentials
        log_info "Trying connection with manual PostgreSQL credentials..."
        if test_postgres_connection "$DB_HOST" "$DB_PORT" "$db_user" "$db_password" "$database"; then
            CONNECTION_VERIFIED=true
            log_success "PostgreSQL connection successful with manual credentials"
            return 0
        else
            log_error "PostgreSQL connection failed with manual credentials"
            log_error "Unable to establish a working PostgreSQL database connection"
            exit 1
        fi
    else
        log_error "Unable to establish a working PostgreSQL database connection"
        exit 1
    fi
}

# Helper function to test PostgreSQL connection
test_postgres_connection() {
    local host=$1
    local port=$2
    local user=$3
    local pass=$4
    local db=$5

    log_debug "Testing PostgreSQL connection to $host:$port with user $user, database $db"

    connection_result=$(python3 - <<EOF
import json
import sys

try:
    import psycopg2
    
    # Set a reasonably short timeout
    conn = psycopg2.connect(
        host='$host',
        port=$port,
        user='$user',
        password='$pass',
        dbname='$db',
        connect_timeout=5
    )

    # Verify we can actually run a query
    cursor = conn.cursor()
    cursor.execute("SELECT 1")
    cursor.fetchone()
    cursor.close()

    conn.close()
    print(json.dumps({"status": "success"}))
except psycopg2.Error as err:
    error_code = str(err.pgcode) if hasattr(err, 'pgcode') else 'unknown'
    error_msg = str(err)
    print(json.dumps({
        "status": "error",
        "error_code": error_code,
        "message": error_msg
    }))
except Exception as e:
    print(json.dumps({
        "status": "error",
        "error_code": "unknown",
        "message": str(e)
    }))
EOF
)

    status=$(echo "$connection_result" | jq -r '.status')

    if [[ "$status" == "success" ]]; then
        return 0
    else
        error_code=$(echo "$connection_result" | jq -r '.error_code')
        message=$(echo "$connection_result" | jq -r '.message')

        log_debug "PostgreSQL connection error ($error_code): $message"
        return 1
    fi
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

    # Verify database connection first
    if [[ "${CONNECTION_VERIFIED:-false}" != "true" ]]; then
        verify_db_connection
    fi
    
    python3 - <<EOF
import psycopg2
import psycopg2.extras
import json
import sys
import uuid
import socket
import hashlib
from datetime import datetime

db_config = {
    "host": "${DB_HOST}",
    "port": ${DB_PORT},
    "user": "${db_user}",
    "password": "${db_password}",
    "database": "${database}",
    "connect_timeout": 10  # Add a reasonable timeout
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
    print(f"[INFO] Connecting to PostgreSQL at {db_config['host']}:{db_config['port']} with user {db_config['user']}")
    conn = psycopg2.connect(**db_config)
    # Use DictCursor to get results as dictionaries
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
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
                query += " WHERE ch.start_date BETWEEN %s::timestamp AND %s::timestamp"
                cursor.execute(query, (f"{start_date} 00:00:00", f"{end_date} 23:59:59"))
            else:
                cursor.execute(query)
                
            records = cursor.fetchall()
            print(f"[INFO] Found {len(records)} connection history records")
            
            for record in records:
                # Convert from DictRow to regular dict
                record_dict = dict(record)
                # Create enhanced SIEM record
                siem_record = add_siem_metadata(record_dict, "connection_history")
                
                # Add network context
                if record_dict.get("protocol"):
                    siem_record["network"] = {
                        "protocol": record_dict["protocol"].lower(),
                        "application_protocol": f"guacamole-{record_dict['protocol'].lower()}",
                        "port": record_dict.get("proxy_port")
                    }
                
                # Add source/destination context
                siem_record["source"] = {
                    "ip": record_dict.get("remote_host"),
                    "user": record_dict.get("username", record_dict.get("entity_id")),
                    "entity_id": record_dict.get("entity_id")
                }
                
                siem_record["destination"] = {
                    "name": record_dict.get("connection_name"),
                    "service": record_dict.get("protocol"),
                    "ip": record_dict.get("proxy_hostname")
                }
                
                # Add session context
                if record_dict.get("start_date") and record_dict.get("end_date"):
                    start = record_dict["start_date"]
                    end = record_dict["end_date"]
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
                elif record_dict.get("start_date") and not record_dict.get("end_date"):
                    siem_record["session"] = {
                        "start": serialize(record_dict["start_date"])
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
                # Convert from DictRow to regular dict
                record_dict = dict(record)
                
                # Secure sensitive data
                if "password_hash" in record_dict:
                    record_dict["password_hash"] = hash_sensitive_data(record_dict["password_hash"])
                if "password_salt" in record_dict:
                    record_dict["password_salt_hash"] = hash_sensitive_data(record_dict["password_salt"])
                    del record_dict["password_salt"]
                    
                # Add SIEM metadata
                siem_record = add_siem_metadata(record_dict, "user_management")
                
                # Add identity context
                siem_record["identity"] = {
                    "entity_id": record_dict.get("entity_id"),
                    "username": record_dict.get("username", ""),
                    "creation_date": serialize(record_dict.get("creation_date")),
                    "last_password_change": serialize(record_dict.get("last_password_change"))
                }
                
                # Attempt to get user permissions - using entity_id instead of user_id
                try:
                    if record_dict.get("entity_id"):
                        cursor.execute("""
                            SELECT permission 
                            FROM guacamole_user_permission 
                            WHERE affected_user_id = %s
                        """, (record_dict.get("entity_id"),))
                        permissions = cursor.fetchall()
                        if permissions:
                            siem_record["permissions"] = [p.get("permission") for p in permissions if p.get("permission")]
                except Exception as e:
                    print(f"[WARNING] Could not retrieve permissions for entity {record_dict.get('entity_id')}: {e}")
                
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
                # Convert from DictRow to regular dict
                record_dict = dict(record)
                
                siem_record = add_siem_metadata(record_dict, "connection_group")
                
                # Add group context
                siem_record["group_details"] = {
                    "group_id": record_dict.get("connection_group_id"),
                    "name": record_dict.get("connection_group_name"),
                    "type": record_dict.get("type"),
                    "parent_id": record_dict.get("parent_id")
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
                # Convert from DictRow to regular dict
                record_dict = dict(record)
                
                siem_record = add_siem_metadata(record_dict, "connection_config")
                
                # Add connection details
                siem_record["connection_details"] = {
                    "connection_id": record_dict.get("connection_id"),
                    "name": record_dict.get("connection_name"),
                    "protocol": record_dict.get("protocol"),
                    "parent_group": record_dict.get("parent_group_name"),
                    "proxy_hostname": record_dict.get("proxy_hostname"),
                    "proxy_port": record_dict.get("proxy_port"),
                    "max_connections": record_dict.get("max_connections"),
                    "max_connections_per_user": record_dict.get("max_connections_per_user")
                }
                
                # Add parameters (through a subquery)
                try:
                    cursor.execute("""
                        SELECT parameter_name, parameter_value
                        FROM guacamole_connection_parameter
                        WHERE connection_id = %s
                    """, (record_dict['connection_id'],))
                    parameters = cursor.fetchall()
                    
                    connection_params = {}
                    sensitive_params = ['password', 'private-key', 'passphrase', 'key-passphrase']
                    
                    for param in parameters:
                        param_dict = dict(param)
                        name = param_dict.get("parameter_name")
                        value = param_dict.get("parameter_value")
                        
                        # Redact sensitive parameters
                        if name in sensitive_params:
                            connection_params[name] = "[REDACTED]"
                        else:
                            connection_params[name] = value
                    
                    if connection_params:
                        siem_record["connection_parameters"] = connection_params
                except Exception as e:
                    print(f"[WARNING] Could not retrieve parameters for connection {record_dict.get('connection_id')}: {e}")
                
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
                # Convert from DictRow to regular dict
                record_dict = dict(record)
                
                # Redact sensitive parameters
                sensitive_params = ['password', 'private-key', 'passphrase', 'key-passphrase']
                if record_dict.get('parameter_name') in sensitive_params:
                    record_dict['parameter_value'] = '[REDACTED]'
                
                siem_record = add_siem_metadata(record_dict, "connection_parameter")
                
                # Add parameter context
                siem_record["parameter"] = {
                    "connection_id": record_dict.get("connection_id"),
                    "connection_name": record_dict.get("connection_name"),
                    "protocol": record_dict.get("protocol"),
                    "name": record_dict.get("parameter_name"),
                    "value": record_dict.get("parameter_value")
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
                # Convert from DictRow to regular dict
                record_dict = dict(record)
                
                siem_record = add_siem_metadata(record_dict, "system_permission")
                
                # Add permission context
                siem_record["permission"] = {
                    "entity_id": record_dict.get("entity_id"),
                    "username": record_dict.get("username"),
                    "permission": record_dict.get("permission"),
                    "permission_description": get_permission_description(record_dict.get("permission"))
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
                file.write(line + "\n")
        print(f"[INFO] Exported {len(cef_output)} records to CEF format")
            
    print("[INFO] Data export completed successfully!")

except psycopg2.Error as err:
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
    if 'conn' in locals() and conn:
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

# Check for Docker compose file and inspect if available
if [[ -f "$COMPOSE_FILE" ]]; then
    log_info "Found docker-compose file, attempting to inspect for database service..."
    DB_SERVICE="db" # Default value if not detected
    
    # Check if docker-compose is installed
    if command -v docker-compose &>/dev/null; then
        # Simple Docker service detection for PostgreSQL
        db_service_detection=$(grep -A 10 "postgres\|postgresql" "$COMPOSE_FILE" | grep -o 'services:.*' | head -1)
        if [[ -n "$db_service_detection" ]]; then
            DB_SERVICE=$(echo "$db_service_detection" | awk '{print $2}')
            log_info "Detected PostgreSQL service: $DB_SERVICE"
        fi
    fi
fi

extract_db_credentials
menu_selection
export_data
verify_export
split_large_files
log_info "Script execution completed successfully."
