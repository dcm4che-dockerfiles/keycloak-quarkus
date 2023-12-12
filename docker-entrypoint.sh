#!/bin/bash

set -e

if [ "$1" = 'kc.sh' ]; then

    . setenv.sh

	  chown -c keycloak:keycloak /opt/keycloak/data /opt/keycloak/themes
    if [ ! -f /opt/keycloak/data/import/dcm4che-realm.json ]; then
      cp -av /docker-entrypoint.d/data /opt/keycloak/
    fi
    if [ ! -f /opt/keycloak/lib/quarkus/build-system.properties ]; then
      cp -av /docker-entrypoint.d/quarkus /opt/keycloak/lib
    fi
    if [ ! -f /opt/keycloak/themes/keycloak/login/theme.properties ]; then
      cp -av /docker-entrypoint.d/themes /opt/keycloak/
    fi
    if [ ! -f $JAVA_HOME/lib/security/cacerts.done ]; then
        touch $JAVA_HOME/lib/security/cacerts.done
        if [ "$EXTRA_CACERTS" ]; then
            keytool -importkeystore \
                -srckeystore $EXTRA_CACERTS -srcstorepass $EXTRA_CACERTS_PASSWORD \
                -destkeystore $JAVA_HOME/lib/security/cacerts -deststorepass changeit
        fi
    fi

    for c in $KEYCLOAK_WAIT_FOR; do
        echo "Waiting for $c ..."
        while ! nc -w 1 -z ${c/:/ }; do sleep 1; done
        echo "done"
    done
    set -- chroot --userspec=keycloak:keycloak / "$@"
    echo "Starting Keycloak $KEYCLOAK_VERSION"
fi

exec "$@"
