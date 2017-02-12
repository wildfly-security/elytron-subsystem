/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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
import static org.jboss.as.controller.PersistentResourceXMLDescription.builder;
import static org.jboss.as.controller.parsing.ParseUtils.requireNoAttributes;
import static org.jboss.as.controller.parsing.ParseUtils.unexpectedElement;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.AUDIT_LOGGING;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.FILE_AUDIT_LOG;
import static org.wildfly.extension.elytron.ElytronSubsystemParser.verifyNamespace;

import java.util.List;

import javax.xml.stream.XMLStreamException;

import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.PersistentResourceXMLDescription;
import org.jboss.dmr.ModelNode;
import org.jboss.staxmapper.XMLExtendedStreamReader;
import org.jboss.staxmapper.XMLExtendedStreamWriter;

/**
 * XML Handling for the audit logging resources.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class AuditLoggingParser {

    private final PersistentResourceXMLDescription fileAuditLogParser = builder(PathElement.pathElement(FILE_AUDIT_LOG), null)
            .setUseElementsForGroups(false)
            .addAttributes(AuditResourceDefinitions.PATH, FileAttributeDefinitions.RELATIVE_TO, AuditResourceDefinitions.SYNCHRONIZED, AuditResourceDefinitions.FORMAT)
            .build();

    void readAuditLogging(ModelNode parentAddressNode, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        requireNoAttributes(reader);
        while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            PathAddress parentAddress = PathAddress.pathAddress(parentAddressNode);
            switch (localName) {
                case FILE_AUDIT_LOG:
                    fileAuditLogParser.parse(reader, parentAddress, operations);
                    break;
                default:
                    throw unexpectedElement(reader);
            }
        }
    }

    void writeAuditLogging(ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (shouldWrite(subsystem) == false) {
            return;
        }

        writer.writeStartElement(AUDIT_LOGGING);

        fileAuditLogParser.persist(writer, subsystem);

        writer.writeEndElement();
    }

    private boolean shouldWrite(ModelNode subsystem) {
        return subsystem.hasDefined(FILE_AUDIT_LOG);
    }

}
