#!/bin/bash

# usage: file_env VAR [DEFAULT]
#    ie: file_env 'XYZ_DB_PASSWORD' 'example'
# (will allow for "$XYZ_DB_PASSWORD_FILE" to fill in the value of
#  "$XYZ_DB_PASSWORD" from a file, especially for Docker's secrets feature)
file_env() {
	local var="$1"
	local fileVar="${var}_FILE"
	local def="${2:-}"
	if [ "${!var:-}" ] && [ "${!fileVar:-}" ]; then
		echo >&2 "error: both $var and $fileVar are set (but are exclusive)"
		exit 1
	fi
	local val="$def"
	if [ "${!var:-}" ]; then
		val="${!var}"
	elif [ "${!fileVar:-}" ]; then
		val="$(< "${!fileVar}")"
	fi
	export "$var"="$val"
	unset "$fileVar"
}

file_env 'LDAP_ROOTPASS' 'secret'
file_env 'KC_DB_USERNAME' 'keycloak'
file_env 'KC_DB_PASSWORD' 'keycloak'
file_env 'KC_BOOTSTRAP_ADMIN_USERNAME'
file_env 'KC_BOOTSTRAP_ADMIN_PASSWORD'
file_env 'KC_HTTPS_KEY_STORE_PASSWORD' 'secret'
file_env 'KC_HTTPS_TRUST_STORE_PASSWORD' 'changeit'
file_env 'KC_SPI_TRUSTSTORE_FILE_PASSWORD' 'changeit'
file_env 'EXTRA_CACERTS_PASSWORD' 'secret'
file_env 'KIBANA_CLIENT_SECRET' 'changeit'
file_env 'ELASTIC_CLIENT_SECRET' 'changeit'
file_env 'RS_CLIENT_SECRET' 'changeit'

if [ -z "$JGROUPS_BIND_IP" ]; then
  if [ -n "$JGROUPS_BIND_IP_PREFIX" ]; then
    for JGROUPS_BIND_IP in $(hostname -I); do if [[ "$JGROUPS_BIND_IP" == "$JGROUPS_BIND_IP_PREFIX"* ]]; then break; fi; done
  else
    JGROUPS_BIND_IP=$(hostname -i)
  fi
  export JGROUPS_BIND_IP
fi
