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

import static javax.xml.stream.XMLStreamConstants.END_ELEMENT;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP_ADDR;
import static org.jboss.as.controller.parsing.ParseUtils.requireNoAttributes;
import static org.jboss.as.controller.parsing.ParseUtils.unexpectedElement;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.DOMAIN;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.DOMAINS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.KEYSTORE;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.KEYSTORES;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PROVIDER_LOADER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PROVIDER_LOADERS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REALMS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.TLS;
import static org.wildfly.extension.elytron.ElytronExtension.NAMESPACE;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.stream.XMLStreamException;

import org.jboss.as.controller.persistence.SubsystemMarshallingContext;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.Property;
import org.jboss.staxmapper.XMLElementReader;
import org.jboss.staxmapper.XMLElementWriter;
import org.jboss.staxmapper.XMLExtendedStreamReader;
import org.jboss.staxmapper.XMLExtendedStreamWriter;

/**
 * The subsystem parser, which uses stax to read and write to and from xml
 *
 * <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ElytronSubsystemParser implements XMLElementReader<List<ModelNode>>, XMLElementWriter<SubsystemMarshallingContext> {

    private final DomainParser domainParser = new DomainParser();
    private final RealmParser realmParser = new RealmParser();
    private final TlsParser tlsParser = new TlsParser();
    private final ProviderLoaderParser providerLoaderParser = new ProviderLoaderParser();

    /**
     * {@inheritDoc}
     */
    @Override
    public void readElement(XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        ModelNode subsystemAdd = ElytronExtension.createAddSubsystemOperation();
        operations.add(subsystemAdd);
        ModelNode parentAddress = subsystemAdd.get(OP_ADDR);

        requireNoAttributes(reader);

        Set<String> foundElements = new HashSet<>();
        while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (foundElements.add(localName) == false) {
                throw unexpectedElement(reader);
            }

            switch (reader.getLocalName()) {
                case PROVIDER_LOADERS:
                    readProviderLoaders(parentAddress, reader, operations);
                    break;
                case DOMAINS:
                    readDomains(parentAddress, reader, operations);
                    break;
                case REALMS:
                    readRealms(parentAddress, reader, operations);
                    break;
                case TLS:
                    readTls(parentAddress, reader, operations);
                    break;
                default:
                    throw unexpectedElement(reader);
            }
        }
    }

    public void readProviderLoaders(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        requireNoAttributes(reader);
        while(reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (PROVIDER_LOADER.equals(localName)) {
               providerLoaderParser.readProviderLoader(parentAddress, reader, operations);
            } else {
                throw unexpectedElement(reader);
            }
        }
    }

    private void readDomains(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        requireNoAttributes(reader);
        while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (DOMAIN.equals(localName)) {
                domainParser.readDomain(parentAddress, reader, operations);
            } else {
                throw unexpectedElement(reader);
            }
        }
    }

    private void readRealms(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        requireNoAttributes(reader);
        while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (REALM.equals(localName)) {
                realmParser.readElement(parentAddress, reader, operations);
            } else {
                throw unexpectedElement(reader);
            }
        }
    }

    private void readTls(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        requireNoAttributes(reader);
        boolean keyStoresFound = false;
        while(reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (KEYSTORES.equals(localName) && keyStoresFound == false) {
                keyStoresFound = true;
                tlsParser.readKeyStores(parentAddress, reader, operations);
            } else {
                throw unexpectedElement(reader);
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void writeContent(XMLExtendedStreamWriter writer, SubsystemMarshallingContext context) throws XMLStreamException {
        context.startSubsystemElement(ElytronExtension.NAMESPACE, false);

        ModelNode model = context.getModelNode();
        if (model.hasDefined(PROVIDER_LOADER)) {
            writer.writeStartElement(PROVIDER_LOADERS);
            for (Property variable : model.get(PROVIDER_LOADER).asPropertyList()) {
                ModelNode providerLoader = variable.getValue();
                providerLoaderParser.writeProviderLoader(variable.getName(), providerLoader, writer);
            }
            writer.writeEndElement();
        }

        if (model.hasDefined(DOMAIN)) {
            writer.writeStartElement(DOMAINS);
            for (Property variable : model.get(DOMAIN).asPropertyList()) {
                ModelNode domain = variable.getValue();
                domainParser.writeDomain(variable.getName(), domain, writer);
            }
            writer.writeEndElement();
        }

        if (model.hasDefined(REALM)) {
            writer.writeStartElement(REALMS);
            for (Property variable : model.get(REALM).asPropertyList()) {
                ModelNode realm = variable.getValue();
                realmParser.writeRealm(variable.getName(), realm, writer);
            }
            writer.writeEndElement();
        }

        boolean hasTlsContent = false;
        boolean hasKeyStore = model.hasDefined(KEYSTORE);
        hasTlsContent = hasTlsContent || hasKeyStore;

        if (hasTlsContent) {
            writer.writeStartElement(TLS);
            if (hasKeyStore) {
                writer.writeStartElement(KEYSTORES);
                for (Property variable : model.get(KEYSTORE).asPropertyList()) {
                    ModelNode keyStore = variable.getValue();
                    tlsParser.writeKeyStore(variable.getName(), keyStore, writer);
                }
                writer.writeEndElement();
            }
            writer.writeEndElement();
        }

        writer.writeEndElement();
    }

    static void verifyNamespace(final XMLExtendedStreamReader reader) throws XMLStreamException {
        if ((NAMESPACE.equals(reader.getNamespaceURI())) == false) {
            throw unexpectedElement(reader);
        }
    }
}