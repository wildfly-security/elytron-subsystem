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

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.ADD;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP_ADDR;
import static org.jboss.as.controller.parsing.ParseUtils.isNoNamespaceAttribute;
import static org.jboss.as.controller.parsing.ParseUtils.missingRequired;
import static org.jboss.as.controller.parsing.ParseUtils.requireNoContent;
import static org.jboss.as.controller.parsing.ParseUtils.unexpectedAttribute;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CLASSES;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.MODULE;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.NAME;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PROVIDER_LOADER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REGISTER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.SLOT;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.stream.XMLStreamException;

import org.jboss.dmr.ModelNode;
import org.jboss.staxmapper.XMLExtendedStreamReader;
import org.jboss.staxmapper.XMLExtendedStreamWriter;

/**
 * A parser specifically for the provider-loader definitions.
 *
 * <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ProviderLoaderParser {

    void readProviderLoader(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        ModelNode operation = new ModelNode();
        operation.get(OP).set(ADD);
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
                    case MODULE:
                        ProviderLoaderDefinition.MODULE.parseAndSetParameter(value, operation, reader);
                        break;
                    case SLOT:
                        ProviderLoaderDefinition.SLOT.parseAndSetParameter(value, operation, reader);
                        break;
                    case CLASSES:
                        for (String className : reader.getListAttributeValue(i)) {
                            ProviderLoaderDefinition.CLASSES.parseAndAddParameterElement(className, operation, reader);
                        }
                        break;
                    case REGISTER:
                        ProviderLoaderDefinition.REGISTER.parseAndSetParameter(value, operation, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        operation.get(OP_ADDR).set(parentAddress).add(PROVIDER_LOADER, name);
        operations.add(operation);

        requireNoContent(reader);
    }

    void writeProviderLoader(String name, ModelNode providerLoader, XMLExtendedStreamWriter writer) throws XMLStreamException {
        writer.writeStartElement(PROVIDER_LOADER);
        writer.writeAttribute(NAME, name);

        ProviderLoaderDefinition.MODULE.marshallAsAttribute(providerLoader, writer);
        ProviderLoaderDefinition.SLOT.marshallAsAttribute(providerLoader, writer);
        ProviderLoaderDefinition.CLASSES.getAttributeMarshaller().marshallAsAttribute(ProviderLoaderDefinition.CLASSES, providerLoader, false, writer);
        ProviderLoaderDefinition.REGISTER.marshallAsAttribute(providerLoader, writer);

        writer.writeEndElement();
    }

}
