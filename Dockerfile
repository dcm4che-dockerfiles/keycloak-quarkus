FROM amazoncorretto:21.0.5-al2023

RUN set -eux \
    && yum install -y findutils hostname shadow-utils nmap-ncat tar gzip unzip \
    && yum clean all \
    && groupadd -r keycloak --gid=1029 \
    && useradd -r -g keycloak --uid=1029 -d /opt/keycloak keycloak

ENV KEYCLOAK_VERSION=26.0.6 \
    DCM4CHE_VERSION=5.33.1

RUN cd $HOME \
    && curl -L https://github.com/keycloak/keycloak/releases/download/$KEYCLOAK_VERSION/keycloak-$KEYCLOAK_VERSION.tar.gz | tar xz \
    && mv keycloak-$KEYCLOAK_VERSION /opt/keycloak \
    && cd /opt/keycloak/providers \
    && curl -fO https://www.dcm4che.org/maven2/org/dcm4che/dcm4che-audit/$DCM4CHE_VERSION/dcm4che-audit-$DCM4CHE_VERSION.jar \
    && curl -fO https://www.dcm4che.org/maven2/org/dcm4che/dcm4che-audit-keycloak/$DCM4CHE_VERSION/dcm4che-audit-keycloak-$DCM4CHE_VERSION.jar \
    && curl -fO https://www.dcm4che.org/maven2/org/dcm4che/dcm4che-conf-api/$DCM4CHE_VERSION/dcm4che-conf-api-$DCM4CHE_VERSION.jar \
    && curl -fO https://www.dcm4che.org/maven2/org/dcm4che/dcm4che-conf-ldap/$DCM4CHE_VERSION/dcm4che-conf-ldap-$DCM4CHE_VERSION.jar \
    && curl -fO https://www.dcm4che.org/maven2/org/dcm4che/dcm4che-conf-ldap-audit/$DCM4CHE_VERSION/dcm4che-conf-ldap-audit-$DCM4CHE_VERSION.jar \
    && curl -fO https://www.dcm4che.org/maven2/org/dcm4che/dcm4che-core/$DCM4CHE_VERSION/dcm4che-core-$DCM4CHE_VERSION.jar \
    && curl -fO https://www.dcm4che.org/maven2/org/dcm4che/dcm4che-net/$DCM4CHE_VERSION/dcm4che-net-$DCM4CHE_VERSION.jar \
    && curl -fO https://www.dcm4che.org/maven2/org/dcm4che/dcm4che-net-audit/$DCM4CHE_VERSION/dcm4che-net-audit-$DCM4CHE_VERSION.jar \
    && chown -R keycloak:keycloak /opt/keycloak \
    && mkdir /docker-entrypoint.d && mv /opt/keycloak/lib/quarkus /docker-entrypoint.d/quarkus

COPY docker-entrypoint.sh setenv.sh /
COPY --chown=keycloak:keycloak conf /opt/keycloak/conf/
COPY --chown=keycloak:keycloak data /docker-entrypoint.d/data/
COPY --chown=keycloak:keycloak themes /docker-entrypoint.d/themes/

ENV REALM_NAME=dcm4che \
    LOGIN_THEME=j4care \
    UI_CLIENT_ID=dcm4chee-arc-ui \
    RS_CLIENT_ID=dcm4chee-arc-rs \
    AUTH_USER_ROLE=auth \
    SUPER_USER_ROLE=root \
    WILDFLY_CONSOLE=wildfly-console \
    WILDFLY_CONSOLE_REDIRECT_URL=https://dcm4chee-arc:9993/console/* \
    KIBANA_CLIENT_ID=kibana \
    KIBANA_REDIRECT_URL=https://kibana:8643/* \
    ELASTIC_CLIENT_ID=elastic \
    ARCHIVE_HOST=dcm4chee-arc \
    ARCHIVE_HTTP_PORT=8080 \
    ARCHIVE_HTTPS_PORT=8443 \
    LDAP_URL=ldap://ldap:389 \
    LDAP_BASE_DN=dc=dcm4che,dc=org \
    SSL_REQUIRED=external \
    VALIDATE_PASSWORD_POLICY=false \
    KC_HTTPS_KEY_STORE_FILE=/opt/keycloak/conf/keystores/key.p12 \
    KC_HTTPS_KEY_STORE_TYPE=PKCS12 \
    KC_HTTPS_TRUST_STORE_FILE=$JAVA_HOME/lib/security/cacerts \
    KC_HTTPS_TRUST_STORE_TYPE=JKS \
    KC_SPI_TRUSTSTORE_FILE_FILE=$JAVA_HOME/lib/security/cacerts \
    KC_SPI_TRUSTSTORE_FILE_HOSTNAME_VERIFICATION_POLICY=ANY \
    EXTRA_CACERTS=/opt/keycloak/conf/keystores/cacerts.p12 \
    KC_LOG_GELF_HOST=logstash \
    DEBUG_PORT=*:8787

ENV PATH /opt/keycloak/bin:$PATH

VOLUME /opt/keycloak/data/
VOLUME /opt/keycloak/lib/quarkus

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["kc.sh", "start", "--import-realm"]
