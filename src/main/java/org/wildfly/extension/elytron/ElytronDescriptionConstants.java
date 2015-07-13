/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.extension.elytron;

/**
 * Constants used in the Elytron subsystem.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
interface ElytronDescriptionConstants {

    String ADD_PREFIX_ROLE_MAPPER = "add-prefix-role-mapper";
    String ADD_SUFFIX_ROLE_MAPPER = "add-suffix-role-mapper";
    String AGGREGATE_NAME_REWRITER = "aggregate-name-rewriter";
    String AGGREGATE_PRINCIPAL_DECODER = "aggregate-principal-decoder";
    String AGGREGATE_REALM = "aggregate-realm";
    String AGGREGATE_ROLE_MAPPER = "aggregate-role-mapper";
    String ALGORITHM = "algorithm";
    String ALIAS = "alias";
    String ATTRIBUTE = "attribute";
    String ATTRIBUTE_MAPPING = "attribute-mapping";
    String AND = "and";
    String AS_RDN = "as-rdn";
    String AUTHENTICATION_LEVEL = "authentication-level";
    String AUTHENTICATION_REALM = "authentication-realm";
    String AUTHORIZATION_REALM = "authorization-realm";
    String BCRYPT_MAPPER = "bcrypt-mapper";
    String CERTIFICATE = "certificate";
    String CERTIFICATES = "certificates";
    String CERTIFICATE_CHAIN = "certificate-chain";
    String CHAINED_NAME_REWRITER = "chained-name-rewriter";
    String CLASS_LOADING = "class-loading";
    String CLASS_NAME = "class-name";
    String CLASS_NAMES = "class-names";
    String CLEAR_PASSWORD_MAPPER = "clear-password-mapper";
    String CONFIGURATION = "configuration";
    String CONFIGURATION_FILE = "configuration-file";
    String CONFIGURATION_PROPERTIES = "configuration-properties";
    String CONSTANT = "constant";
    String CONSTANT_NAME_REWRITER = "constant-name-rewriter";
    String CONSTANT_ROLE_MAPPER = "constant-role-mapper";
    String CORE_SERVICE = "core-service";
    String CREATION_DATE = "creation-date";
    String CREDENTIAL = "credential";
    String CUSTOM_NAME_REWRITER = "custom-name-rewriter";
    String CUSTOM_PERMISSION_MAPPER = "custom-permission-mapper";
    String CUSTOM_PRINCIPAL_DECODER = "custom-principal-decoder";
    String CUSTOM_REALM = "custom-realm";
    String CUSTOM_REALM_MAPPER = "custom-realm-mapper";
    String CUSTOM_ROLE_DECODER = "custom-role-decoder";
    String CUSTOM_ROLE_MAPPER = "custom-role-mapper";
    String DATA_SOURCE = "data-source";
    String DEFAULT_REALM = "default-realm";
    String DELEGATE_REALM_MAPPER = "delegate-realm-mapper";
    String DIR_CONTEXT = "dir-context";
    String ENABLE_CONNECTION_POOLING = "enable-connection-pooling";
    String ENCODED = "encoded";
    String EMPTY_ROLE_DECODER = "empty-role-decoder";
    String ENTRY_TYPE = "entry-type";
    String FILE = "file";
    String FILESYSTEM_REALM = "filesystem-realm";
    String FILTER = "filter";
    String FILTER_BASE_DN = "filter-base-dn";
    String FINGER_PRINT = "finger-print";
    String FINGER_PRINTS = "finger-prints";
    String FORMAT = "format";
    String FROM = "from";
    String GROUPS_PROPERTIES = "groups-properties";
    String IMPLEMENTATION = "implementation";
    String INDEX = "index";
    String INFO = "info";
    String ISSUER = "issuer";
    String ITERATION_COUNT_INDEX = "iteration-count-index";
    String JAAS_REALM = "jaas-realm";
    String JDBC_REALM = "jdbc-realm";
    String JOINER = "joiner";
    String KEY = "key";
    String KEYSTORE = "keystore";
    String KEYSTORE_REALM = "keystore-realm";
    String KEYSTORES = "keystores";
    String LDAP_REALM = "ldap-realm";
    String LEFT = "left";
    String LEVELS = "levels";
    String LOAD = "load";
    String LOADED_PROVIDER = "loaded-provider";
    String LOADED_PROVIDERS = "loaded-providers";
    String LOAD_SERVICES = "load-services";
    String LOGICAL_OPERATION = "logical-operation";
    String LOGICAL_ROLE_MAPPER = "logical-role-mapper";
    String MAPPED_REGEX_REALM_MAPPER = "mapped-regex-realm-mapper";
    String MAXIMUM_SEGMENTS = "maximum-segments";
    String MATCH = "match";
    String MAPPERS = "mappers";
    String MINUS = "minus";
    String MODIFIED = "modified";
    String MODULE = "module";
    String MODULE_REFERENCE = "module-reference";
    String NAME = "name";
    String NAME_REWRITER = "name-rewriter";
    String NAME_REWRITERS = "name-rewriters";
    String NOT_AFTER = "not-after";
    String NOT_BEFORE = "not-before";
    String OID = "oid";
    String OR = "or";
    String PATH = "path";
    String PATTERN = "pattern";
    String PASSWORD = "password";
    String PASSWORD_INDEX = "password-index";
    String PERMISSION_MAPPER = "permission-mapper";
    String PLAIN_TEXT = "plain-text";
    String POST_REALM_NAME_REWRITER = "post-realm-name-rewriter";
    String PRE_REALM_NAME_REWRITER = "pre-realm-name-rewriter";
    String PREFIX = "prefix";
    String PRINCIPAL = "principal";
    String PRINCIPAL_DECODER = "principal-decoder";
    String PRINCIPAL_DECODERS = "principal-decoders";
    String PRINCIPAL_MAPPING = "principal-mapping";
    String PRINCIPAL_QUERY = "principal-query";
    String PROPERTIES_REALM = "properties-realm";
    String PROPERTY = "property";
    String PROPERTY_LIST = "property-list";
    String PROVIDER = "provider";
    String PROVIDERS = "providers";
    String PROVIDER_LOADER = "provider-loader";
    String PROVIDER_LOADERS = "provider-loaders";
    String PUBLIC_KEY = "public-key";
    String RDN_IDENTIFIER = "rdn-identifier";
    String REALM_MAP = "realm-map";
    String REALM_MAPPER = "realm-mapper";
    String REALM_MAPPING = "realm-mapping";
    String REALM = "realm";
    String REALMS = "realms";
    String REGEX_NAME_REWRITER = "regex-name-rewriter";
    String REGEX_NAME_VALIDATING_REWRITER = "regex-name-validating-rewriter";
    String REGISTER = "register";
    String RELATIVE_TO = "relative-to";
    String REPLACE_ALL = "replace-all";
    String REPLACEMENT = "replacement";
    String REQUIRED = "required";
    String RIGHT = "right";
    String ROLE_DECODER = "role-decoder";
    String ROLE_MAPPER = "role-mapper";
    String ROLE_MAPPERS = "role-mappers";
    String ROLES = "roles";
    String SEARCH_BASE_DN = "search-base-dn";
    String SECURITY_DOMAIN = "security-domain";
    String SECURITY_DOMAINS = "security-domains";
    String SECURITY_REALMS = "security-realms";
    String SALT_INDEX = "salt-index";
    String SALTED_SIMPLE_DIGEST_MAPPER = "salted-simple-digest-mapper";
    String SCRAM_MAPPER = "scram-mapper";
    String SECURITY_PROPERTIES = "security-properties";
    String SECURITY_PROPERTY = "security-property";
    String SERIAL_NUMBER = "serial-number";
    String SERVICE = "service";
    String SERVICES = "services";
    String SIGNATURE = "signature";
    String SIGNATURE_ALGORITHM = "signature-algorithm";
    String SIMPLE_DIGEST_MAPPER = "simple-digest-mapper";
    String SIMPLE_REGEX_REALM_MAPPER = "simple-regex-realm-mapper";
    String SIMPLE_ROLE_DECODER = "simple-role-decoder";
    String SIZE = "size";
    String SLOT = "slot";
    String SQL = "sql";
    String STATE = "state";
    String STORE = "store";
    String SUBJECT = "subject";
    String SUFFIX = "suffix";
    String SYNCHRONIZED = "synchronized";
    String TLS = "tls";
    String TO = "to";
    String TYPE = "type";
    String URL = "url";
    String USE_RECURSIVE_SEARCH = "use-recursive-search";
    String USERS_PROPERTIES = "users-properties";
    String VALUE = "value";
    String VERSION = "version";
    String WATCH = "watch";
    String X500_ATTRIBUTE_PRINCIPAL_DECODER = "x500-attribute-principal-decoder";
    String XOR = "xor";
}

