# Keycloak Docker image

This docker image provides [Keycloak Authentication Server](https://www.keycloak.org/) initialized for securing the
DICOM Archive [dcm4chee-arc-light](https://github.com/dcm4che/dcm4chee-arc-light/wiki).

## How to use this image

See [Running on Docker](https://github.com/dcm4che/dcm4chee-arc-light/wiki/Running-on-Docker) at the
[dcm4che Archive 5 Wiki](https://github.com/dcm4che/dcm4chee-arc-light/wiki).

## Environment Variables 

Below explained environment variables can be set as per one's application to override the default values if need be.
An example of how one can set an env variable in `docker run` command is shown below :

    -e KEYCLOAK_DEVICE_NAME=my-keycloak

_**Note**_ : If default values of any environment variables were overridden in startup of `slapd` container, 
then ensure that the same values are also used for overriding the defaults during startup of keycloak container. 

### Environment variables referred by Realm Configuration imported on first Startup:
#### `REALM_NAME`

Realm name (default is `dcm4che`).

#### `SSL_REQUIRED`

Defining the SSL/HTTPS requirements for interacting with the realm:
- `none` - HTTPS is not required for any client IP address
- `external` - private IP addresses can access without HTTPS
- `all` - HTTPS is required for all IP addresses

(default is `external`).

#### `VALIDATE_PASSWORD_POLICY`

Indicates if Keycloak should validate the password with the realm password policy before updating it
(default value is `false`).

#### `UI_CLIENT_ID`

Keycloak client ID for securing the UI of the archive (optional, default is `dcm4chee-arc-ui`).

#### `WILDFLY_CONSOLE`

Keycloak client ID for [securing the Wildfly Administration Console](https://docs.jboss.org/author/display/WFLY/Protecting+Wildfly+Adminstration+Console+With+Keycloak)
of the archive (optional, default is `wildfly-console`).

#### `ARCHIVE_HOST`

Hostname of the archive device referred by OIDC Keycloak clients for securing the UI
and the Wildfly Administration Console of the archive. Default value is `dcm4chee-arc`.

#### `ARCHIVE_HTTP_PORT`

HTTP port of the UI of the archive (optional, default is `8080`).

#### `ARCHIVE_HTTPS_PORT`

HTTPS port of the UI of the archive (optional, default is `8443`).

#### `ARCHIVE_MANAGEMENT_HTTPS_PORT`

HTTPS port of Wildfly Administration Console of the archive (optional, default is `9993`).

#### `KIBANA_CLIENT_ID`

Keycloak client ID for securing the UI of Kibana (optional, default is `kibana`).

#### `KIBANA_CLIENT_SECRET`

Secret for Keycloak client for securing the UI of Kibana (optional, default is `changeit`).

#### `KIBANA_CLIENT_SECRET_FILE`

File containing secret for Keycloak client for securing the UI of Kibana (alternative to `KIBANA_CLIENT_SECRET`).

#### `KIBANA_ROOT_URL`

Root URL of Keycloak client for securing the UI of Kibana (optional, default is `https://kibana:8643`).

#### `ELASTIC_CLIENT_ID`

Keycloak client ID for securing access to Elasticsearch (optional, default is `elastic`).

#### `ELASTIC_CLIENT_SECRET`

Secret for Keycloak client for securing access to Elasticsearch (optional, default is `changeit`).

#### `ELASTIC_CLIENT_SECRET_FILE`

File containing secret for Keycloak client for securing access to Elasticsearch (alternative to `ELASTIC_CLIENT_SECRET`).

#### `ELASTIC_ROOT_URL`

Root URL of Keycloak client for securing access to Elasticsearch (optional, default is `https://elastic:8943`).

### Configuring LDAP connection for User Federation of Realm and fetching Audit Logger configuration:
#### `LDAP_URL`

URL for accessing LDAP (optional, default is `ldap://ldap:389`).

#### `LDAP_BASE_DN`

Base domain name for LDAP (optional, default is `dc=dcm4che,dc=org`).

#### `LDAP_ROOTPASS`

Password to use to authenticate to LDAP (optional, default is `secret`).

#### `LDAP_ROOTPASS_FILE`

Password to use to authenticate to LDAP via file input (alternative to `LDAP_ROOTPASS`).

#### `LDAP_DISABLE_HOSTNAME_VERIFICATION`

Indicates to disable the verification of the hostname of the certificate of the LDAP server,
if using TLS (`LDAP_URL=ldaps://<host>:<port>`) (optional, default is `true`).

#### `KEYCLOAK_DEVICE_NAME`

Device name to lookup in LDAP for Audit Logger configuration (optional, default is `keycloak`).

#### `SUPER_USER_ROLE`

User role to identify super users, which have unrestricted access to all UI functions of the Archive. Login/Logout of
such users will emit an [Audit Message for Security Alert](http://dicom.nema.org/medical/dicom/current/output/html/part15.html#sect_A.5.3.11)
with _Event Type Code_: `(110127,DCM,"Emergency Override Started")`/`(110138,DCM,"Emergency Override Stopped")`.
Optional, default is `root`.

### Setup of the initial admin user
#### `KEYCLOAK_ADMIN`

By default there is no admin user created so you won't be able to login to the admin console of the Keycloak master
realm at `https://${KC_HOSTNAME}:${KC_HTTPS_PORT}[/${KC_HTTP_RELATIVE_PATH}]`. To create an admin account you may use
environment variables `KEYCLOAK_ADMIN` and `KEYCLOAK_ADMIN_PASSWORD` to pass in an initial username and password.
Once the first user with administrative rights exists, you may use the UI to change the initial password,
create additional admin users and/or delete that initial admin user.

#### `KEYCLOAK_ADMIN_FILE`

Keycloak admin user via file input (alternative to KEYCLOAK_USER).

#### `KEYCLOAK_ADMIN_PASSWORD`

User's password to use to authenticate to the Keycloak master realm.

#### `KEYCLOAK_ADMIN_PASSWORD_FILE`

User's password to use to authenticate to the Keycloak master realm via file input (alternative to KEYCLOAK_PASSWORD).

### Configuring the hostname and context path
#### `KC_HOSTNAME`
Hostname for the Keycloak server.

#### `KC_HTTP_RELATIVE_PATH`

Set the path relative to '/' for serving resources. (optional, default is `/`).

### Configuring [OpenID Connect Logout](https://www.keycloak.org/docs/latest/upgrading/index.html#openid-connect-logout)
#### `KC_SPI_LOGIN_PROTOCOL_OPENID_CONNECT_LEGACY_LOGOUT_REDIRECT_URI`

Enable backwards compatibility option `legacy-logout-redirect-uri` of oidc login protocol in the server configuration (default value is `false`).
Required for logout by UI of current archive version (5.26.1). 

### [Configuring TLS](https://www.keycloak.org/server/enabletls):
#### `KC_HTTP_ENABLED`

Enables the HTTP listener (default value is `false`).

#### `KC_HTTP_PORT`

HTTP port of Keycloak (optional, default is `8080`). Only effective with `KC_HTTP_ENABLED` is `true`.

#### `KC_HTTPS_PORT`

HTTPS port of Wildfly (optional, default is `8443`).

#### `KC_HTTPS_KEY_STORE_FILE`

Path to keystore file with private key and certificate for HTTPS (default is
`/opt/keycloak/conf/keystore/key.p12`, with sample key + certificate:
```
Subject    - CN=PACS_J4C,O=J4CARE,C=AT
Issuer     - CN=IHE Europe CA, O=IHE Europe, C=FR
Valid From - Sun Apr 02 06:38:46 UTC 2017
Valid To   - Fri Apr 02 06:38:46 UTC 2027
MD5 : 7a:b3:f7:5d:cf:6e:84:34:be:5a:7a:12:95:fa:46:76
SHA1 : a9:36:b3:b4:60:63:22:9e:f4:ae:41:d3:3b:97:ca:be:9b:a9:32:e9
```
provided by the docker image only for testing purpose).

#### `KC_HTTPS_KEY_STORE_PASSWORD`

Password used to protect the integrity of the keystore specified by `KEYSTORE` (default is `secret`).

#### `KC_HTTPS_KEY_STORE_PASSWORD_FILE`

Password used to protect the integrity of the keystore specified by `KEYSTORE` via file input
(alternative to `KEYSTORE_PASSWORD`).

#### `KC_HTTPS_KEY_STORE_TYPE`

Type (`JKS` or `PKCS12`) of the keystore specified by `KEYSTORE` (default is `PKCS12`).

#### `KC_HTTPS_TRUST_STORE_FILE`

Path to keystore file with trusted certificates for TLS (optional, default is the default Java truststore
`/usr/local/openjdk-11/lib/security/cacerts`). s.o. [EXTRA_CACERTS](#extra_cacerts).

#### `KC_HTTPS_TRUST_STORE_PASSWORD`

Password used to protect the integrity of the keystore specified by `TRUSTSTORE` (optional, default is `changeit`).

#### `KC_HTTPS_TRUST_STORE_PASSWORD_FILE`

Password used to protect the integrity of the keystore specified by `TRUSTSTORE` via file input
(alternative to `TRUSTSTORE_PASSWORD`).

#### `KC_HTTPS_TRUST_STORE_TYPE`

Type (`JKS` or `PKCS12`) of the keystore specified by `TRUSTSTORE` (optional, default is `JKS`).

#### `EXTRA_CACERTS`

Path to keystore file with CA certificates imported to default Java truststore (optional, default is
`/opt/keycloak/conf/keystore/cacerts.p12`, with sample CA certificate:
```
Subject    - CN=IHE Europe CA,O=IHE Europe,C=FR
Issuer     - CN=IHE Europe CA,O=IHE Europe,C=FR
Valid From - Fri Sep 28 11:19:29 UTC 2012
Valid To   - Wed Sep 28 11:19:29 UTC 2022
MD5 : 64:b6:1b:0f:8d:84:17:da:23:e4:e5:1c:56:ba:06:5d
SHA1 : 54:e0:10:c6:4a:fe:2c:aa:20:3f:50:95:45:82:cb:53:55:6b:07:7f
```
provided by the docker image only for testing purpose).

#### `EXTRA_CACERTS_PASSWORD`

Password used to protect the integrity of the keystore specified by `EXTRA_CACERTS` (optional, default is `secret`).

#### `EXTRA_CACERTS_PASSWORD_FILE`

Password used to protect the integrity of the keystore specified by `EXTRA_CACERTS` via file input
(alternative to `EXTRA_CACERTS_PASSWORD`).

#### `KC_HTTPS_PROTOCOLS`

Comma separated list of enabled TLS protocols (`SSLv2`, `SSLv3`, `TLSv1`, `TLSv1.1`, `TLSv1.2`, `TLSv1.3`)
(optional, default is `TLSv1.3`). 

#### `KC_HTTPS_CIPHER_SUITES`

The cipher suites to use. If none is given, a reasonable default is selected.

#### `KC_PROXY`

The proxy address forwarding mode if the server is behind a reverse proxy.
Accepted values are:
- `edge` - Enables communication through HTTP between the proxy and Keycloak. This mode is suitable for deployments with a highly secure internal network where the reverse proxy keeps a secure connection (HTTP over TLS) with clients while communicating with Keycloak using HTTP..
- `reencrypt` - Requires communication through HTTPS between the proxy and Keycloak. This mode is suitable for deployments where internal communication between the reverse proxy and Keycloak should also be protected. Different keys and certificates are used on the reverse proxy as well as on Keycloak.
- `passthrough` - Enables communication through HTTP or HTTPS between the proxy and Keycloak. This mode is suitable for deployments where the reverse proxy is not terminating TLS. The proxy instead is forwarding requests to the Keycloak server so that secure connections between the server and clients are based on the keys and certificates used by the Keycloak server.

s. [Using a reverse proxy](https://www.keycloak.org/server/reverseproxy)

### [Configuring outgoing HTTP requests](https://www.keycloak.org/server/outgoinghttp):
#### `KC_SPI_TRUSTSTORE_FILE_HOSTNAME_VERIFICATION_POLICY`

Specifies if Keycloak shall verify the hostname of the server’s certificate on outgoing HTTPS requests.
Accepted values are:
- `ANY` - the hostname is not verified.
- `WILDCARD` - allows wildcards in subdomain names i.e. `*.foo.com`.
- `STRICT` - CN must match hostname exactly.

Default value is `ANY`.

#### `KC_SPI_CONNECTIONS_HTTP_CLIENT_DEFAULT_DISABLE_TRUST_MANAGER`
If `true`, certificate checking will include the [default set of root CA certificates in the JDK](https://openjdk.java.net/jeps/319)
additionally to CA certificates in `TRUSTSTORE` (optional, default is `false`).

### JVM related Environment variables: 
#### `JAVA_OPTS`

Java VM options (optional, default is `"-Xms64m -Xmx512m -XX:MetaspaceSize=96M -XX:MaxMetaspaceSize=256m -Djava.net.preferIPv4Stack=true"`).

#### `JAVA_OPTS_APPEND`

Additional Java properties to append to `JAVA_OPTS`.

#### `DEBUG`

If `true`,  start JPDA listener for remote socket debugging on local binding address and port specified by `DEBUG_PORT`
(optional, default is `false`).

#### `DEBUG_PORT`

Specify local binding address and port `<addr>:<port>` for JPDA remote socket debugging, if `DEBUG` is `true`
or with command option `--debug` (optional, default is `*:8787`).

#### `KEYCLOAK_WAIT_FOR`

Indicates to delay the start of keycloak until specified TCP ports become accessible. Format: `<host>:<port> ...`, e.g.: `ldap:389 logstash:8514`.

### [Keycloak Database configuration](https://www.keycloak.org/server/db):
#### `KC_DB`

The database vendor:
- `mariadb` - use external MariaDB database,
- `mssql` - use external Microsoft SQL Server database,
- `mysql` - use external MySQL and MariaDB database,
- `oracle` - use external Oracle database,
- `postgres` - use external PostgreSQL database,

(optional, default use embedded H2 database).

#### `KC_DB_SCHEMA`

The database schema to be used.

#### `KC_DB_URL`

JDBC driver connection URL.
Optional, default JDBC URL depends on external database.

#### `KC_DB_URL_DATABASE`

Sets the database name of the default JDBC URL of the chosen vendor.

#### `KC_DB_URL_HOST`

Sets the hostname of the default JDBC URL of the chosen vendor.

#### `KC_DB_URL_PORT`

Sets the port of the default JDBC URL of the chosen vendor.

#### `KC_DB_URL_PROPERTIES`

Sets the properties of the default JDBC URL of the chosen vendor.

#### `KC_DB_USERNAME`

User to authenticate to the external database (optional, default is `keycloak`).

#### `KC_DB_USERNAME_FILE`

User to authenticate to the external database via file input (alternative to `KC_DB_USERNAME`).

#### `KC_DB_PASSWORD`

User's password to use to authenticate to the external database (optional, default is `keycloak`).

#### `KC_DB_PASSWORD_FILE`

User's password to use to authenticate to the external database via file input (alternative to `DB_PASSWORD`).

#### `KC_DB_POOL_INITIAL_SIZE`

The initial size of the connection pool.

#### `KC_DB_POOL_MAX_SIZE`

The maximum size of the connection pool (optional, default is `100`).

#### `KC_DB_POOL_MIN_SIZE`

The minimum size of the connection pool.

#### `KC_TRANSACTION_XA_ENABLED`

Manually override the transaction type (optional, default is `true`).


### [Logging configuration](https://www.keycloak.org/server/logging):

#### `KC_LOG`

Enabled log handlers:
- `console` - console log handler (=default)
- `file` - file log handler
- `console,file` - console and file log handler

#### `KC_LOG_FILE`
Set the log file path and filename (optional, default is `/opt/keycloak/data/log/keycloak.log`).

#### `KC_LOG_FILE_FORMAT`
Set a format specific to file log entries (optional, default is `%d{yyyy-MM-dd HH:mm:ss,SSS} %-5p [%c] (%t) %s%e%n`).

#### `KC_LOG_LEVEL`
The log level of the root category or a comma-separated list of individual categories and their levels
(optional, default is `INFO`). E.g.: `INFO,org.infinispan:DEBUG,org.jgroups:DEBUG`.

### [Logstash/GELF Logger](https://logging.paluch.biz/) configuration:

#### `GELF_ENABLED`

Whether emitting system logs to [Logstash](https://www.elastic.co/products/logstash) is enabled (optional, default is `false`).

#### `LOGSTASH_HOST`

Hostname/IP-Address of the Logstash host. (optional, default is `logstash`).

#### `LOGSTASH_PORT`

Port of the Logstash host. (optional, default is `12201`).

#### `GELF_VERSION`

GELF Version 1.0 or 1.1 (optional, default is `1.1`).

#### `GELF_FACILITY`

Name of the Facility (optional, default is `keycloak`).

#### `GELF_LEVEL`

Log-Level threshold (optional, default is `WARN`).

#### `GELF_EXTRACT_STACK_TRACE`

Indicates if the Stack-Trace shall be sent in the StackTrace field (optional, default is `true`).

#### `GELF_FILTER_STACK_TRACE`

Indicates if Stack-Trace filtering shall be performed (optional, default is `true`).

### [Cluster JDBC_PING configuration](https://github.com/ivangfr/keycloak-clustered):

Requires use of external MySQL, MariaDB, Postgres or Microsoft SQL Server database to persist data.

#### `KC_CACHE_CONFIG_FILE`

Specify included `cache-ispn-jdbc-ping.xml` as cache configuration file.

#### `JGROUPS_BIND_IP`

JGroups server socket bind address (optional, default `$(hostname -i)` or select particular container IP according `JGROUPS_BIND_IP_PREFIX`).

#### `JGROUPS_BIND_IP_PREFIX`

JGroups server socket bind address prefix used to select particular container IP if no `JGROUPS_BIND_IP` is specified.

#### `JGROUPS_TCP_PORT`

JGroups TCP stack port (optional, default is `7600`).

#### `JGROUPS_DISCOVERY_EXTERNAL_IP`

IP address of this host - must be accessible by the other Keycloak instances.
