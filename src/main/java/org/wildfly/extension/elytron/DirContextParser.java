/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

import org.jboss.dmr.ModelNode;
import org.jboss.staxmapper.XMLExtendedStreamReader;
import org.jboss.staxmapper.XMLExtendedStreamWriter;

import javax.xml.stream.XMLStreamException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.NAME;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.SSL_CONTEXT;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.URL;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.AUTHENTICATION_LEVEL;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PRINCIPAL;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CREDENTIAL;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.ENABLE_CONNECTION_POOLING;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REFERRAL_MODE;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.DIR_CONTEXT;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.DIR_CONTEXTS;
import static org.wildfly.extension.elytron.ElytronSubsystemParser.verifyNamespace;

/**
 * A parser for the DirContext definition.
 *
 * <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class DirContextParser {

    void readDirContexts(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        requireNoAttributes(reader);
        while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (DIR_CONTEXT.equals(localName)) {
                readDirContext(parentAddress, reader, operations);
            } else {
                throw unexpectedElement(reader);
            }
        }
    }

    void readDirContext(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        ModelNode addDirContext = new ModelNode();
        addDirContext.get(OP).set(ADD);

        Set<String> requiredXmlAttributes = new HashSet<>(Arrays.asList(new String[]{ NAME, URL }));

        String name = null;
        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                requiredXmlAttributes.remove(attribute);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    case URL:
                        DirContextDefinition.URL.parseAndSetParameter(value, addDirContext, reader);
                        break;
                    case AUTHENTICATION_LEVEL:
                        DirContextDefinition.AUTHENTICATION_LEVEL.parseAndSetParameter(value, addDirContext, reader);
                        break;
                    case PRINCIPAL:
                        DirContextDefinition.PRINCIPAL.parseAndSetParameter(value, addDirContext, reader);
                        break;
                    case CREDENTIAL:
                        DirContextDefinition.CREDENTIAL.parseAndSetParameter(value, addDirContext, reader);
                        break;
                    case ENABLE_CONNECTION_POOLING:
                        DirContextDefinition.ENABLE_CONNECTION_POOLING.parseAndSetParameter(value, addDirContext, reader);
                        break;
                    case REFERRAL_MODE:
                        DirContextDefinition.REFERRAL_MODE.parseAndSetParameter(value, addDirContext, reader);
                        break;
                    case SSL_CONTEXT:
                        DirContextDefinition.SSL_CONTEXT.parseAndSetParameter(value, addDirContext, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredXmlAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredXmlAttributes);
        }
        requireNoContent(reader);

        addDirContext.get(OP_ADDR).set(parentAddress).add(DIR_CONTEXT, name);
        operations.add(addDirContext);
    }

    void writeDirContexts(ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(DIR_CONTEXT)) {
            writer.writeStartElement(DIR_CONTEXTS);
            ModelNode dirContexts = subsystem.require(DIR_CONTEXT);
            for (String name : dirContexts.keys()) {
                ModelNode dirContext = dirContexts.require(name);
                writer.writeStartElement(DIR_CONTEXT);
                writer.writeAttribute(NAME, name);
                DirContextDefinition.URL.marshallAsAttribute(dirContext, writer);
                DirContextDefinition.AUTHENTICATION_LEVEL.marshallAsAttribute(dirContext, writer);
                DirContextDefinition.PRINCIPAL.marshallAsAttribute(dirContext, writer);
                DirContextDefinition.CREDENTIAL.marshallAsAttribute(dirContext, writer);
                DirContextDefinition.ENABLE_CONNECTION_POOLING.marshallAsAttribute(dirContext, writer);
                DirContextDefinition.REFERRAL_MODE.marshallAsAttribute(dirContext, writer);
                writer.writeEndElement();
            }
            writer.writeEndElement();
        }
    }

}
