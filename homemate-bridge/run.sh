#!/usr/bin/with-contenv bashio

# Load required config values
token_required_vars=(
    'keys' 'mqtt_username' 'mqtt_password' 'mqtt_host' 'mqtt_port'
)
missing_vars=()
for var in "${token_required_vars[@]}"; do
    value=$(bashio::config "$var")
    if [ -z "$value" ] || [ "$value" = "null" ]; then
        missing_vars+=("$var")
    fi
done

if [ ${#missing_vars[@]} -ne 0 ]; then
    bashio::log.error "The following required config variables are missing: ${missing_vars[*]}"
    exit 1
fi

# Read all config values
to_file_if_set() {
    local value="$1"
    local path="$2"
    if [ -n "$value" ] && [ "$value" != "null" ]; then
        printf '%s' "$value" >"$path"
        echo "$path"
    else
        echo ""
    fi
}

# Helper to treat 'null' as unset for variables
null_to_empty() {
    local value="$1"
    if [ "$value" = "null" ]; then
        echo ""
    else
        echo "$value"
    fi
}

KEYS=$(null_to_empty "$(bashio::config 'keys')")
DEVICES=$(null_to_empty "$(bashio::config 'devices')")
HOMEMATE_PORT=$(null_to_empty "$(bashio::config 'homemate_port')")
MQTT_CLIENT_ID=$(null_to_empty "$(bashio::config 'mqtt_client_id')")
MQTT_USERNAME=$(null_to_empty "$(bashio::config 'mqtt_username')")
MQTT_PASSWORD=$(null_to_empty "$(bashio::config 'mqtt_password')")
MQTT_HOST=$(null_to_empty "$(bashio::config 'mqtt_host')")
MQTT_PORT=$(null_to_empty "$(bashio::config 'mqtt_port')")
MQTT_TLS_CACERT=$(null_to_empty "$(bashio::config 'mqtt_tls_cacert')")
MQTT_TLS_CERTFILE=$(null_to_empty "$(bashio::config 'mqtt_tls_certfile')")
MQTT_TLS_KEYFILE=$(null_to_empty "$(bashio::config 'mqtt_tls_keyfile')")
DISCOVERY_PREFIX=$(null_to_empty "$(bashio::config 'discovery_prefix')")
NODE_ID=$(null_to_empty "$(bashio::config 'node_id')")

# Write keys and devices files
KEYS_FILE="/tmp/keys.json"
printf '%s' "$KEYS" >"$KEYS_FILE"

DEVICES_ARG=""
if [ -n "$DEVICES" ]; then
    DEVICES_FILE="/tmp/devices.json"
    printf '%s' "$DEVICES" >"$DEVICES_FILE"
    DEVICES_ARG="--devices-file=$DEVICES_FILE"
fi

# Write TLS files if provided
MQTT_TLS_CACERT_FILE=$(to_file_if_set "$MQTT_TLS_CACERT" "/tmp/mqtt_tls_cacert.pem")
MQTT_TLS_CERTFILE_FILE=$(to_file_if_set "$MQTT_TLS_CERTFILE" "/tmp/mqtt_tls_certfile.pem")
MQTT_TLS_KEYFILE_FILE=$(to_file_if_set "$MQTT_TLS_KEYFILE" "/tmp/mqtt_tls_keyfile.pem")

# Build arguments for homemate-bridge
ARGS=(
    --keys-file="$KEYS_FILE"
)
if [ -n "$DEVICES_ARG" ]; then
    ARGS+=("$DEVICES_ARG")
fi
if [ -n "$HOMEMATE_PORT" ]; then
    ARGS+=(--homemate-port="$HOMEMATE_PORT")
fi
if [ -n "$MQTT_CLIENT_ID" ]; then
    ARGS+=(--mqtt-client-id="$MQTT_CLIENT_ID")
fi
ARGS+=(
    --mqtt-username="$MQTT_USERNAME"
    --mqtt-password="$MQTT_PASSWORD"
    --mqtt-host="$MQTT_HOST"
    --mqtt-port="$MQTT_PORT"
)
if [ -n "$MQTT_TLS_CACERT_FILE" ]; then
    ARGS+=(--mqtt-tls-cacert="$MQTT_TLS_CACERT_FILE")
fi
if [ -n "$MQTT_TLS_CERTFILE_FILE" ]; then
    ARGS+=(--mqtt-tls-certfile="$MQTT_TLS_CERTFILE_FILE")
fi
if [ -n "$MQTT_TLS_KEYFILE_FILE" ]; then
    ARGS+=(--mqtt-tls-keyfile="$MQTT_TLS_KEYFILE_FILE")
fi
if [ -n "$DISCOVERY_PREFIX" ]; then
    ARGS+=(--discovery-prefix="$DISCOVERY_PREFIX")
fi
if [ -n "$NODE_ID" ]; then
    ARGS+=(--node-id="$NODE_ID")
fi

# Run homemate-bridge with all arguments
echo "Running homemate-bridge with arguments: ${ARGS[*]}"
/opt/venv/bin/homemate-bridge "${ARGS[@]}"
