FROM eclipse-temurin:11.0.17_8-jdk

# explicitly set user/group IDs
RUN groupadd -r keycloak --gid=1029 && useradd -r -g keycloak --uid=1029 -d /opt/keycloak keycloak

# grab gosu for easy step-down from root
ENV GOSU_VERSION 1.14
RUN arch="$(dpkg --print-architecture)" \
    && set -x \
    && apt-get update \
    && apt-get install -y gnupg netcat-openbsd unzip \
    && rm -rf /var/lib/apt/lists/* \
    && curl -o /usr/local/bin/gosu -fSL "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$arch" \
    && curl -o /usr/local/bin/gosu.asc -fSL "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$arch.asc" \
    && export GNUPGHOME="$(mktemp -d)" \
    && gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4 \
    && gpg --batch --verify /usr/local/bin/gosu.asc /usr/local/bin/gosu \
    && gpgconf --kill all \
    && rm -rf "$GNUPGHOME" /usr/local/bin/gosu.asc \
    && chmod +x /usr/local/bin/gosu \
    && gosu --version \
    && gosu nobody true

ENV KEYCLOAK_VERSION=20.0.1 \
    DCM4CHE_VERSION=5.29.1

RUN cd $HOME \
    && curl -L https://github.com/keycloak/keycloak/releases/download/$KEYCLOAK_VERSION/keycloak-$KEYCLOAK_VERSION.tar.gz | tar xz \
    && mv keycloak-$KEYCLOAK_VERSION /opt/keycloak \
    && cd /opt/keycloak/providers \
    && curl -O https://www.dcm4che.org/maven2/org/dcm4che/dcm4che-audit/$DCM4CHE_VERSION/dcm4che-audit-$DCM4CHE_VERSION.jar \
    && curl -O https://www.dcm4che.org/maven2/org/dcm4che/dcm4che-audit-keycloak/$DCM4CHE_VERSION/dcm4che-audit-keycloak-$DCM4CHE_VERSION.jar \
    && curl -O https://www.dcm4che.org/maven2/org/dcm4che/dcm4che-conf-api/$DCM4CHE_VERSION/dcm4che-conf-api-$DCM4CHE_VERSION.jar \
    && curl -O https://www.dcm4che.org/maven2/org/dcm4che/dcm4che-conf-ldap/$DCM4CHE_VERSION/dcm4che-conf-ldap-$DCM4CHE_VERSION.jar \
    && curl -O https://www.dcm4che.org/maven2/org/dcm4che/dcm4che-conf-ldap-audit/$DCM4CHE_VERSION/dcm4che-conf-ldap-audit-$DCM4CHE_VERSION.jar \
    && curl -O https://www.dcm4che.org/maven2/org/dcm4che/dcm4che-core/$DCM4CHE_VERSION/dcm4che-core-$DCM4CHE_VERSION.jar \
    && curl -O https://www.dcm4che.org/maven2/org/dcm4che/dcm4che-net/$DCM4CHE_VERSION/dcm4che-net-$DCM4CHE_VERSION.jar \
    && curl -O https://www.dcm4che.org/maven2/org/dcm4che/dcm4che-net-audit/$DCM4CHE_VERSION/dcm4che-net-audit-$DCM4CHE_VERSION.jar \
    && chown -R keycloak:keycloak /opt/keycloak \
    && mkdir /docker-entrypoint.d

COPY docker-entrypoint.sh setenv.sh /
COPY --chown=keycloak:keycloak conf /opt/keycloak/conf/
COPY --chown=keycloak:keycloak data /docker-entrypoint.d/data/
COPY --chown=keycloak:keycloak themes /docker-entrypoint.d/themes/

ENV REALM_NAME=dcm4che \
    UI_CLIENT_ID=dcm4chee-arc-ui \
    RS_CLIENT_ID=dcm4chee-arc-rs \
    AUTH_USER_ROLE=user \
    WILDFLY_CONSOLE=wildfly-console \
    KIBANA_CLIENT_ID=kibana \
    KIBANA_REDIRECT_URL=https://kibana:8643/* \
    ELASTIC_CLIENT_ID=elastic \
    ARCHIVE_HOST=dcm4chee-arc \
    ARCHIVE_HTTP_PORT=8080 \
    ARCHIVE_HTTPS_PORT=8443 \
    ARCHIVE_MANAGEMENT_HTTPS_PORT=9993 \
    LDAP_URL=ldap://ldap:389 \
    LDAP_BASE_DN=dc=dcm4che,dc=org \
    SSL_REQUIRED=external \
    VALIDATE_PASSWORD_POLICY=false \
    KC_HTTPS_KEY_STORE_FILE=/opt/keycloak/conf/keystores/key.p12 \
    KC_HTTPS_KEY_STORE_TYPE=PKCS12 \
    KC_HTTPS_TRUST_STORE_FILE=/opt/java/openjdk/lib/security/cacerts \
    KC_HTTPS_TRUST_STORE_TYPE=JKS \
    KC_SPI_TRUSTSTORE_FILE_FILE=/opt/java/openjdk/lib/security/cacerts \
    KC_SPI_TRUSTSTORE_FILE_HOSTNAME_VERIFICATION_POLICY=ANY \
    EXTRA_CACERTS=/opt/keycloak/conf/keystores/cacerts.p12 \
    KC_LOG_GELF_HOST=logstash \
    DEBUG_PORT=*:8787

ENV PATH /opt/keycloak/bin:$PATH

VOLUME /opt/keycloak/data/

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["kc.sh", "start", "--import-realm"]
