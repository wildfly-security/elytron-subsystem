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

    String AGGREGATE_NAME_REWRITER = "aggregate-name-rewriter";
    String AGGREGATE_REALM = "aggregate-realm";
    String ALGORITHM = "algorithm";
    String ALIAS = "alias";
    String ATTRIBUTE = "attribute";
    String AUTHENTICATION_LEVEL = "authentication-level";
    String AUTHENTICATION_REALM = "authentication-realm";
    String AUTHORIZATION_REALM = "authorization-realm";
    String CACHE_PRINCIPAL = "cache-principal";
    String CERTIFICATE = "certificate";
    String CERTIFICATES = "certificates";
    String CERTIFICATE_CHAIN = "certificate-chain";
    String CLASS_LOADING = "class-loading";
    String CLASS_NAME = "class-name";
    String CLASS_NAMES = "class-names";
    String CONFIGURATION = "configuration";
    String CONFIGURATION_FILE = "configuration-file";
    String CONFIGURATION_PROPERTIES = "configuration-properties";
    String CORE_SERVICE = "core-service";
    String CREATION_DATE = "creation-date";
    String CREDENTIAL = "credential";
    String CUSTOM_NAME_REWRITER = "custom-name-rewriter";
    String CUSTOM_REALM = "custom-realm";
    String CUSTOM_REALM_MAPPER = "custom-realm-mapper";
    String CUSTOM_ROLE_DECODER = "custom-role-decoder";
    String DEFAULT_REALM = "default_realm";
    String DELEGATE_REALM_MAPPER = "delegate-realm-mapper";
    String DIR_CONTEXT = "dir-context";
    String ENCODED = "encoded";
    String EMPTY_ROLE_DECODER = "empty-role-decoder";
    String ENTRY_TYPE = "entry-type";
    String FILE = "file";
    String FINGER_PRINT = "finger-print";
    String FINGER_PRINTS = "finger-prints";
    String FORMAT = "format";
    String FROM = "from";
    String GROUPS_PROPERTIES = "groups-properties";
    String IMPLEMENTATION = "implementation";
    String INDEX = "index";
    String INFO = "info";
    String ISSUER = "issuer";
    String JAAS_REALM = "jaas-realm";
    String KEY = "key";
    String KEYSTORE = "keystore";
    String KEYSTORE_REALM = "keystore-realm";
    String KEYSTORES = "keystores";
    String LDAP_REALM = "ldap-realm";
    String LOAD = "load";
    String LOADED_PROVIDER = "loaded-provider";
    String LOADED_PROVIDERS = "loaded-providers";
    String LOAD_SERVICES = "load-services";
    String MAPPED_REGEX_REALM_MAPPER = "mapped-regex-realm-mapper";
    String MATCH = "match";
    String MAPPERS = "mappers";
    String MODIFIED = "modified";
    String MODULE = "module";
    String MODULE_REFERENCE = "module-reference";
    String NAME = "name";
    String NAME_ATTRIBUTE = "name-attribute";
    String NAME_REWRITER = "name-rewriter";
    String NAME_REWRITERS = "name-rewriters";
    String NOT_AFTER = "not-after";
    String NOT_BEFORE = "not-before";
    String PATH = "path";
    String PATTERN = "pattern";
    String PASSWORD = "password";
    String PLAIN_TEXT = "plain-text";
    String POST_REALM_NAME_REWRITER = "post-realm-name-rewriter";
    String PRE_REALM_NAME_REWRITER = "pre-realm-name-rewriter";
    String PRINCIPAL = "principal";
    String PRINCIPAL_MAPPING = "principal-mapping";
    String PROPERTIES_REALM = "properties-realm";
    String PROPERTY = "property";
    String PROPERTY_LIST = "property-list";
    String PROVIDER = "provider";
    String PROVIDERS = "providers";
    String PROVIDER_LOADER = "provider-loader";
    String PROVIDER_LOADERS = "provider-loaders";
    String PUBLIC_KEY = "public-key";
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
    String SEARCH_BASE_DN = "search-base-dn";
    String SECURITY_DOMAIN = "security-domain";
    String SECURITY_DOMAINS = "security-domains";
    String SECURITY_PROPERTIES = "security-properties";
    String SECURITY_PROPERTY = "security-property";
    String SERIAL_NUMBER = "serial-number";
    String SERVICE = "service";
    String SERVICES = "services";
    String SIGNATURE = "signature";
    String SIGNATURE_ALGORITHM = "signature-algorithm";
    String SIMPLE_REGEX_REALM_MAPPER = "simple-regex-realm-mapper";
    String SIMPLE_ROLE_DECODER = "simple-role-decoder";
    String SIZE = "size";
    String SLOT = "slot";
    String STATE = "state";
    String STORE = "store";
    String SUBJECT = "subject";
    String SYNCHRONIZED = "synchronized";
    String TLS = "tls";
    String TO = "to";
    String TYPE = "type";
    String URL = "url";
    String USE_X500_NAME = "use-x500-name";
    String USE_X500_PRINCIPAL = "use-x500-principal";
    String USE_RECURSIVE_SEARCH = "use-recursive-search";
    String USERS_PROPERTIES = "users-properties";
    String VALUE = "value";
    String VERSION = "version";
    String WATCH = "watch";

}
