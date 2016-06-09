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


import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.ADD;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP_ADDR;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUBSYSTEM;
import static org.wildfly.extension.elytron.ElytronSubsystemUtil.CAPABILITIES_INITIALIZATION;

import java.util.List;

import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.subsystem.test.AbstractSubsystemTest;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.as.subsystem.test.KernelServicesBuilder;
import org.jboss.dmr.ModelNode;
import org.junit.Assert;
import org.junit.Test;


/**
 * Tests all management expects for subsystem, parsing, marshaling, model definition and other
 * Here is an example that allows you a fine grained controller over what is tested and how. So it can give you ideas what can be done and tested.
 * If you have no need for advanced testing of subsystem you look at {@link SubsystemBaseParsingTestCase} that tests same stuff but most of the code
 * is hidden inside of test harness
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
public class SubsystemParsingTestCase extends AbstractSubsystemTest {

    public SubsystemParsingTestCase() {
        super(ElytronExtension.SUBSYSTEM_NAME, new ElytronExtension());
    }

    /**
     * Tests that the xml is parsed into the correct operations
     */
    @Test
    public void testParseSubsystem() throws Exception {
        //Parse the subsystem xml into operations
        String subsystemXml =
                "<subsystem xmlns=\"" + ElytronExtension.NAMESPACE + "\">" +
                        "</subsystem>";
        List<ModelNode> operations = super.parse(subsystemXml);

        ///Check that we have the expected number of operations
        Assert.assertEquals(1, operations.size());

        //Check that each operation has the correct content
        ModelNode addSubsystem = operations.get(0);
        Assert.assertEquals(ADD, addSubsystem.get(OP).asString());
        PathAddress addr = PathAddress.pathAddress(addSubsystem.get(OP_ADDR));
        Assert.assertEquals(1, addr.size());
        PathElement element = addr.getElement(0);
        Assert.assertEquals(SUBSYSTEM, element.getKey());
        Assert.assertEquals(ElytronExtension.SUBSYSTEM_NAME, element.getValue());
    }

    /**
     * Test that the model created from the xml looks as expected
     */
    @Test
    public void testInstallIntoController() throws Exception {
        //Parse the subsystem xml and install into the controller
        String subsystemXml =
                "<subsystem xmlns=\"" + ElytronExtension.NAMESPACE + "\">" +
                        "</subsystem>";
        KernelServices services = super.createKernelServicesBuilder(null).setSubsystemXml(subsystemXml).build();

        //Read the whole model and make sure it looks as expected
        ModelNode model = services.readWholeModel();
        Assert.assertTrue(model.get(SUBSYSTEM).hasDefined(ElytronExtension.SUBSYSTEM_NAME));
    }

    /**
     * Starts a controller with a given subsystem xml and then checks that a second
     * controller started with the xml marshalled from the first one results in the same model
     */
    @Test
    public void testParseAndMarshalModel() throws Exception {
        //Parse the subsystem xml and install into the first controller
        String subsystemXml =
                "<subsystem xmlns=\"" + ElytronExtension.NAMESPACE + "\">" +
                        "</subsystem>";
        KernelServices servicesA = super.createKernelServicesBuilder(null).setSubsystemXml(subsystemXml).build();
        //Get the model and the persisted xml from the first controller
        ModelNode modelA = servicesA.readWholeModel();
        String marshalled = servicesA.getPersistedSubsystemXml();

        //Install the persisted xml from the first controller into a second controller
        KernelServices servicesB = super.createKernelServicesBuilder(null).setSubsystemXml(marshalled).build();
        ModelNode modelB = servicesB.readWholeModel();

        //Make sure the models from the two controllers are identical
        super.compare(modelA, modelB);
    }

    /**
     * Starts a controller with a given subsystem xml and then checks that a second
     * controller started with the xml marshalled from the first one results in the same model
     */
    private void testParseAndMarshalModel(final String fileName) throws Exception {
        //Parse the subsystem xml and install into the first controller
        KernelServices servicesA = createKernelServicesBuilder().setSubsystemXmlResource(fileName).build();

        //Get the model and the persisted xml from the first controller
        ModelNode modelA = servicesA.readWholeModel();
        System.out.println(modelA.toString());
        String marshalled = servicesA.getPersistedSubsystemXml();
        System.out.println(marshalled);

        //Install the persisted xml from the first controller into a second controller
        KernelServices servicesB = createKernelServicesBuilder().setSubsystemXml(marshalled).build();
        ModelNode modelB = servicesB.readWholeModel();

        //Make sure the models from the two controllers are identical
        super.compare(modelA, modelB);
    }

    private KernelServicesBuilder createKernelServicesBuilder() {
        return super.createKernelServicesBuilder(CAPABILITIES_INITIALIZATION);
    }

    @Test
    public void testParseAndMarshalModel_Domain() throws Exception {
        testParseAndMarshalModel("domain.xml");
    }

    @Test
    public void testParseAndMarshalModel_TLS() throws Exception {
        testParseAndMarshalModel("tls.xml");
    }

    @Test
    public void testParseAndMarshalModel_ProviderLoader() throws Exception {
        testParseAndMarshalModel("provider-loader.xml");
    }

    @Test
    public void testParseAndMarshalModel_CredentialSecurityFactories() throws Exception {
        testParseAndMarshalModel("credential-security-factories.xml");
    }

    @Test
    public void testParseAndMarshalModel_Mappers() throws Exception {
        testParseAndMarshalModel("mappers.xml");
    }

    @Test
    public void testParseAndMarshalModel_Http() throws Exception {
        testParseAndMarshalModel("http.xml");
    }

    @Test
    public void testParseAndMarshalModel_Sasl() throws Exception {
        testParseAndMarshalModel("sasl.xml");
    }

    @Test
    public void testParseAndMarshalModel_Realms() throws Exception {
        testParseAndMarshalModel("security-realms.xml");
    }

    @Test
    public void testParseAndMarshalModel_SecurityProperties() throws Exception {
        testParseAndMarshalModel("security-properties.xml");
    }

    /**
     * Tests that the subsystem can be removed
     */
    @Test
    public void testSubsystemRemoval() throws Exception {
        //Parse the subsystem xml and install into the first controller
        String subsystemXml =
                "<subsystem xmlns=\"" + ElytronExtension.NAMESPACE + "\">" +
                        "</subsystem>";
        KernelServices services = super.createKernelServicesBuilder(null).setSubsystemXml(subsystemXml).build();
        //Checks that the subsystem was removed from the model
        super.assertRemoveSubsystemResources(services);

        //TODO Check that any services that were installed were removed here
    }
}
