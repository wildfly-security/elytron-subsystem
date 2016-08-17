/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

import static javax.xml.stream.XMLStreamConstants.END_ELEMENT;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.ADD;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP_ADDR;
import static org.jboss.as.controller.parsing.ParseUtils.isNoNamespaceAttribute;
import static org.jboss.as.controller.parsing.ParseUtils.missingRequired;
import static org.jboss.as.controller.parsing.ParseUtils.requireNoAttributes;
import static org.jboss.as.controller.parsing.ParseUtils.requireNoContent;
import static org.jboss.as.controller.parsing.ParseUtils.unexpectedAttribute;
import static org.jboss.as.controller.parsing.ParseUtils.unexpectedElement;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.ALGORITHM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.ALIAS_FILTER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.AUTHENTICATION_OPTIONAL;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CIPHER_SUITE_FILTER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.FILE;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.KEY_MANAGER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.KEY_MANAGERS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.KEY_STORE;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.KEY_STORES;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.MAXIMUM_SESSION_CACHE_SIZE;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.NAME;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.NEED_CLIENT_AUTH;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PASSWORD;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PATH;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PROTOCOLS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PROVIDER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PROVIDER_LOADER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.RELATIVE_TO;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REQUIRED;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.SECURITY_DOMAIN;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.SERVER_SSL_CONTEXT;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.SERVER_SSL_CONTEXTS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CLIENT_SSL_CONTEXT;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CLIENT_SSL_CONTEXTS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.SESSION_TIMEOUT;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.TLS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.TRUST_MANAGER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.TRUST_MANAGERS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.TYPE;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.WANT_CLIENT_AUTH;
import static org.wildfly.extension.elytron.ElytronSubsystemParser.verifyNamespace;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.stream.XMLStreamException;

import org.jboss.dmr.ModelNode;
import org.jboss.staxmapper.XMLExtendedStreamReader;
import org.jboss.staxmapper.XMLExtendedStreamWriter;

/**
 * A parser for the TLS related definitions.
 *
 * <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class TlsParser {

    void readTls(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        requireNoAttributes(reader);
        boolean keyManagersFound = false;
        boolean keyStoresFound = false;
        boolean trustManagersFound = false;
        boolean serverSSLContextsFound = false;
        boolean clientSSLContextsFound = false;

        while(reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (KEY_MANAGERS.equals(localName) && keyManagersFound == false) {
                keyManagersFound = true;
                readKeyManagers(parentAddress, reader, operations);
            } else if (KEY_STORES.equals(localName) && keyStoresFound == false) {
                keyStoresFound = true;
                readKeyStores(parentAddress, reader, operations);
            } else if (TRUST_MANAGERS.equals(localName) && trustManagersFound == false) {
                trustManagersFound = true;
                readTrustManagers(parentAddress, reader, operations);
            } else if (SERVER_SSL_CONTEXTS.equals(localName) && serverSSLContextsFound == false) {
                serverSSLContextsFound = true;
                readServerSSLContexts(parentAddress, reader, operations);
            } else if (CLIENT_SSL_CONTEXTS.equals(localName) && clientSSLContextsFound == false) {
                clientSSLContextsFound = true;
                readClientSSLContexts(parentAddress, reader, operations);
            } else {
                throw unexpectedElement(reader);
            }
        }
    }

    private void readKeyManagers(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        requireNoAttributes(reader);
        while(reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (KEY_MANAGER.equals(localName)) {
                readKeyManager(parentAddress, reader, operations);
            } else {
                throw unexpectedElement(reader);
            }
        }
    }

    private void readKeyManager(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> list) throws XMLStreamException {
        ModelNode addKeyManager = new ModelNode();
        addKeyManager.get(OP).set(ADD);
        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME, ALGORITHM }));
        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                requiredAttributes.remove(attribute);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    case ALGORITHM:
                        SSLDefinitions.ALGORITHM.parseAndSetParameter(value, addKeyManager, reader);
                        break;
                    case KEY_STORE:
                        SSLDefinitions.KEYSTORE.parseAndSetParameter(value, addKeyManager, reader);
                        break;
                    case PROVIDER:
                        SSLDefinitions.PROVIDER_LOADER.parseAndSetParameter(value, addKeyManager, reader);
                        break;
                    case PASSWORD:
                        SSLDefinitions.PASSWORD.parseAndSetParameter(value, addKeyManager, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        addKeyManager.get(OP_ADDR).set(parentAddress).add(KEY_MANAGERS, name);
        list.add(addKeyManager);

        requireNoContent(reader);
    }

    private void readTrustManagers(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        requireNoAttributes(reader);
        while(reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (TRUST_MANAGER.equals(localName)) {
                readTrustManager(parentAddress, reader, operations);
            } else {
                throw unexpectedElement(reader);
            }
        }
    }

    private void readTrustManager(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> list) throws XMLStreamException {
        ModelNode addKeyManager = new ModelNode();
        addKeyManager.get(OP).set(ADD);
        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME, ALGORITHM }));
        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                requiredAttributes.remove(attribute);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    case ALGORITHM:
                        SSLDefinitions.ALGORITHM.parseAndSetParameter(value, addKeyManager, reader);
                        break;
                    case KEY_STORE:
                        SSLDefinitions.KEYSTORE.parseAndSetParameter(value, addKeyManager, reader);
                        break;
                    case PROVIDER:
                        SSLDefinitions.PROVIDER_LOADER.parseAndSetParameter(value, addKeyManager, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        addKeyManager.get(OP_ADDR).set(parentAddress).add(TRUST_MANAGERS, name);
        list.add(addKeyManager);

        requireNoContent(reader);
    }

    private void readServerSSLContexts(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        requireNoAttributes(reader);
        while(reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (SERVER_SSL_CONTEXT.equals(localName)) {
                readServerSSLContext(parentAddress, reader, operations);
            } else {
                throw unexpectedElement(reader);
            }
        }
    }

    private void readServerSSLContext(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> list) throws XMLStreamException {
        ModelNode addServerSSLContext = new ModelNode();
        addServerSSLContext.get(OP).set(ADD);
        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME }));
        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                requiredAttributes.remove(attribute);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    case SECURITY_DOMAIN:
                        SSLDefinitions.SECURITY_DOMAIN.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    case CIPHER_SUITE_FILTER:
                        SSLDefinitions.CIPHER_SUITE_FILTER.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    case PROTOCOLS:
                        for (String protocol : reader.getListAttributeValue(i)) {
                            SSLDefinitions.PROTOCOLS.parseAndAddParameterElement(protocol, addServerSSLContext, reader);
                        }
                        break;
                    case WANT_CLIENT_AUTH:
                        SSLDefinitions.WANT_CLIENT_AUTH.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    case NEED_CLIENT_AUTH:
                        SSLDefinitions.NEED_CLIENT_AUTH.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    case AUTHENTICATION_OPTIONAL:
                        SSLDefinitions.AUTHENTICATION_OPTIONAL.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    case MAXIMUM_SESSION_CACHE_SIZE:
                        SSLDefinitions.MAXIMUM_SESSION_CACHE_SIZE.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    case SESSION_TIMEOUT:
                        SSLDefinitions.SESSION_TIMEOUT.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    case KEY_MANAGERS:
                        SSLDefinitions.KEY_MANAGERS.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    case TRUST_MANAGERS:
                        SSLDefinitions.TRUST_MANAGERS.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    case PROVIDER:
                        SSLDefinitions.PROVIDER_LOADER.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        addServerSSLContext.get(OP_ADDR).set(parentAddress).add(SERVER_SSL_CONTEXT, name);
        list.add(addServerSSLContext);

        requireNoContent(reader);
    }

    private void readClientSSLContexts(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        requireNoAttributes(reader);
        while(reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (CLIENT_SSL_CONTEXT.equals(localName)) {
                readClientSSLContext(parentAddress, reader, operations);
            } else {
                throw unexpectedElement(reader);
            }
        }
    }

    private void readClientSSLContext(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> list) throws XMLStreamException {
        ModelNode addServerSSLContext = new ModelNode();
        addServerSSLContext.get(OP).set(ADD);
        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME }));
        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                requiredAttributes.remove(attribute);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    case SECURITY_DOMAIN:
                        SSLDefinitions.SECURITY_DOMAIN.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    case CIPHER_SUITE_FILTER:
                        SSLDefinitions.CIPHER_SUITE_FILTER.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    case PROTOCOLS:
                        for (String protocol : reader.getListAttributeValue(i)) {
                            SSLDefinitions.PROTOCOLS.parseAndAddParameterElement(protocol, addServerSSLContext, reader);
                        }
                        break;
                    case WANT_CLIENT_AUTH:
                        SSLDefinitions.WANT_CLIENT_AUTH.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    case NEED_CLIENT_AUTH:
                        SSLDefinitions.NEED_CLIENT_AUTH.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    case AUTHENTICATION_OPTIONAL:
                        SSLDefinitions.AUTHENTICATION_OPTIONAL.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    case MAXIMUM_SESSION_CACHE_SIZE:
                        SSLDefinitions.MAXIMUM_SESSION_CACHE_SIZE.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    case SESSION_TIMEOUT:
                        SSLDefinitions.SESSION_TIMEOUT.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    case KEY_MANAGERS:
                        SSLDefinitions.KEY_MANAGERS.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    case TRUST_MANAGERS:
                        SSLDefinitions.TRUST_MANAGERS.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    case PROVIDER:
                        SSLDefinitions.PROVIDER_LOADER.parseAndSetParameter(value, addServerSSLContext, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        addServerSSLContext.get(OP_ADDR).set(parentAddress).add(CLIENT_SSL_CONTEXT, name);
        list.add(addServerSSLContext);

        requireNoContent(reader);
    }

    private void readKeyStores(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        requireNoAttributes(reader);
        while(reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (KEY_STORE.equals(localName)) {
                readKeyStore(parentAddress, reader, operations);
            } else {
                throw unexpectedElement(reader);
            }
        }
    }

    private void readKeyStore(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> list) throws XMLStreamException {
        ModelNode addKeyStore = new ModelNode();
        addKeyStore.get(OP).set(ADD);
        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME, TYPE }));
        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                requiredAttributes.remove(attribute);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    case TYPE:
                        KeyStoreDefinition.TYPE.parseAndSetParameter(value, addKeyStore, reader);
                        break;
                    case PROVIDER:
                        KeyStoreDefinition.PROVIDER.parseAndSetParameter(value, addKeyStore, reader);
                        break;
                    case PROVIDER_LOADER:
                        KeyStoreDefinition.PROVIDER_LOADER.parseAndSetParameter(value, addKeyStore, reader);
                        break;
                    case PASSWORD:
                        KeyStoreDefinition.PASSWORD.parseAndSetParameter(value, addKeyStore, reader);
                        break;
                    case ALIAS_FILTER:
                        KeyStoreDefinition.ALIAS_FILTER.parseAndSetParameter(value, addKeyStore, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        addKeyStore.get(OP_ADDR).set(parentAddress).add(KEY_STORE, name);
        list.add(addKeyStore);

        while(reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (FILE.equals(localName)) {
                readFile(addKeyStore, reader, list);
            } else {
                throw unexpectedElement(reader);
            }
        }

    }

    private void readFile(ModelNode addOp, XMLExtendedStreamReader reader, List<ModelNode> list) throws XMLStreamException {
        boolean pathFound = false;
        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                switch (attribute) {
                    case RELATIVE_TO:
                        FileAttributeDefinitions.RELATIVE_TO.parseAndSetParameter(value, addOp, reader);
                        break;
                    case PATH:
                        pathFound = true;
                        FileAttributeDefinitions.PATH.parseAndSetParameter(value, addOp, reader);
                        break;
                    case REQUIRED:
                        KeyStoreDefinition.REQUIRED.parseAndSetParameter(value, addOp, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (pathFound == false) {
            throw missingRequired(reader, PATH);
        }
        requireNoContent(reader);
    }

    private void startTLS(boolean started, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (started == false) {
            writer.writeStartElement(TLS);
        }
    }

    void writeTLS(ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        boolean tlsStarted = false;

        tlsStarted = tlsStarted | writeKeyStores(tlsStarted, subsystem, writer);
        tlsStarted = tlsStarted | writeKeyManagers(tlsStarted, subsystem, writer);
        tlsStarted = tlsStarted | writeTrustManagers(tlsStarted, subsystem, writer);
        tlsStarted = tlsStarted | writeServerSSLContext(tlsStarted, subsystem, writer);
        tlsStarted = tlsStarted | writeClientSSLContext(tlsStarted, subsystem, writer);

        if (tlsStarted) {
            writer.writeEndElement();
        }
    }

    private boolean writeKeyManagers(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(KEY_MANAGERS)) {
            startTLS(started, writer);
            writer.writeStartElement(KEY_MANAGERS);
            ModelNode keyManagers = subsystem.require(KEY_MANAGERS);
            for (String name : keyManagers.keys()) {
                ModelNode keyManager = keyManagers.require(name);
                writer.writeStartElement(KEY_MANAGER);
                writer.writeAttribute(NAME, name);
                SSLDefinitions.ALGORITHM.marshallAsAttribute(keyManager, writer);
                SSLDefinitions.KEYSTORE.marshallAsAttribute(keyManager, writer);
                SSLDefinitions.PROVIDER_LOADER.marshallAsAttribute(keyManager, writer);
                SSLDefinitions.PASSWORD.marshallAsAttribute(keyManager, writer);

                writer.writeEndElement();
            }

            writer.writeEndElement();
            return true;
        }

        return false;
    }

    private boolean writeTrustManagers(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(TRUST_MANAGERS)) {
            startTLS(started, writer);
            writer.writeStartElement(TRUST_MANAGERS);
            ModelNode trustManagers = subsystem.require(TRUST_MANAGERS);
            for (String name : trustManagers.keys()) {
                ModelNode trustManager = trustManagers.require(name);
                writer.writeStartElement(TRUST_MANAGER);
                writer.writeAttribute(NAME, name);
                SSLDefinitions.ALGORITHM.marshallAsAttribute(trustManager, writer);
                SSLDefinitions.KEYSTORE.marshallAsAttribute(trustManager, writer);
                SSLDefinitions.PROVIDER_LOADER.marshallAsAttribute(trustManager, writer);

                writer.writeEndElement();
            }

            writer.writeEndElement();
            return true;
        }

        return false;
    }

    private boolean writeServerSSLContext(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(SERVER_SSL_CONTEXT)) {
            startTLS(started, writer);
            writer.writeStartElement(SERVER_SSL_CONTEXTS);
            ModelNode serverSSLContexts = subsystem.require(SERVER_SSL_CONTEXT);

            for (String name : serverSSLContexts.keys()) {
                ModelNode serverSSLContext = serverSSLContexts.require(name);
                writer.writeStartElement(SERVER_SSL_CONTEXT);
                writer.writeAttribute(NAME, name);
                SSLDefinitions.SECURITY_DOMAIN.marshallAsAttribute(serverSSLContext, writer);
                SSLDefinitions.CIPHER_SUITE_FILTER.marshallAsAttribute(serverSSLContext, writer);
                SSLDefinitions.PROTOCOLS.getAttributeMarshaller().marshallAsAttribute(SSLDefinitions.PROTOCOLS, serverSSLContext, false, writer);
                SSLDefinitions.WANT_CLIENT_AUTH.marshallAsAttribute(serverSSLContext, writer);
                SSLDefinitions.NEED_CLIENT_AUTH.marshallAsAttribute(serverSSLContext, writer);
                SSLDefinitions.AUTHENTICATION_OPTIONAL.marshallAsAttribute(serverSSLContext, writer);
                SSLDefinitions.MAXIMUM_SESSION_CACHE_SIZE.marshallAsAttribute(serverSSLContext, writer);
                SSLDefinitions.SESSION_TIMEOUT.marshallAsAttribute(serverSSLContext, writer);
                SSLDefinitions.KEY_MANAGERS.marshallAsAttribute(serverSSLContext, writer);
                SSLDefinitions.TRUST_MANAGERS.marshallAsAttribute(serverSSLContext, writer);
                SSLDefinitions.PROVIDER_LOADER.marshallAsAttribute(serverSSLContext, writer);

                writer.writeEndElement();
            }

            writer.writeEndElement();
            return true;
        }

        return false;
    }

    private boolean writeClientSSLContext(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(CLIENT_SSL_CONTEXT)) {
            startTLS(started, writer);
            writer.writeStartElement(CLIENT_SSL_CONTEXTS);
            ModelNode serverSSLContexts = subsystem.require(CLIENT_SSL_CONTEXT);

            for (String name : serverSSLContexts.keys()) {
                ModelNode serverSSLContext = serverSSLContexts.require(name);
                writer.writeStartElement(CLIENT_SSL_CONTEXT);
                writer.writeAttribute(NAME, name);
                SSLDefinitions.SECURITY_DOMAIN.marshallAsAttribute(serverSSLContext, writer);
                SSLDefinitions.CIPHER_SUITE_FILTER.marshallAsAttribute(serverSSLContext, writer);
                SSLDefinitions.PROTOCOLS.getAttributeMarshaller().marshallAsAttribute(SSLDefinitions.PROTOCOLS, serverSSLContext, false, writer);
                SSLDefinitions.MAXIMUM_SESSION_CACHE_SIZE.marshallAsAttribute(serverSSLContext, writer);
                SSLDefinitions.SESSION_TIMEOUT.marshallAsAttribute(serverSSLContext, writer);
                SSLDefinitions.KEY_MANAGERS.marshallAsAttribute(serverSSLContext, writer);
                SSLDefinitions.TRUST_MANAGERS.marshallAsAttribute(serverSSLContext, writer);
                SSLDefinitions.PROVIDER_LOADER.marshallAsAttribute(serverSSLContext, writer);

                writer.writeEndElement();
            }

            writer.writeEndElement();
            return true;
        }

        return false;
    }

    private boolean writeKeyStores(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(KEY_STORE)) {
            startTLS(started, writer);
            writer.writeStartElement(KEY_STORES);
            ModelNode keystores = subsystem.require(KEY_STORE);
            for (String name : keystores.keys()) {
                ModelNode keyStore = keystores.require(name);
                writer.writeStartElement(KEY_STORE);
                writer.writeAttribute(NAME, name);
                KeyStoreDefinition.TYPE.marshallAsAttribute(keyStore, writer);
                KeyStoreDefinition.PROVIDER.marshallAsAttribute(keyStore, writer);
                KeyStoreDefinition.PROVIDER_LOADER.marshallAsAttribute(keyStore, writer);
                KeyStoreDefinition.PASSWORD.marshallAsAttribute(keyStore, writer);
                KeyStoreDefinition.ALIAS_FILTER.marshallAsAttribute(keyStore, writer);

                if (keyStore.hasDefined(PATH)) {
                    writer.writeStartElement(FILE);
                    FileAttributeDefinitions.RELATIVE_TO.marshallAsAttribute(keyStore, writer);
                    FileAttributeDefinitions.PATH.marshallAsAttribute(keyStore, writer);
                    KeyStoreDefinition.REQUIRED.marshallAsAttribute(keyStore, writer);

                    writer.writeEndElement();
                }
                writer.writeEndElement();
            }

            writer.writeEndElement();
            return true;
        }

        return false;
    }


}
