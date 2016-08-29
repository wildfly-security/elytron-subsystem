/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2016 Red Hat, Inc. and/or its affiliates.
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

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import org.jboss.as.controller.client.helpers.ClientConstants;
import org.jboss.as.subsystem.test.AbstractSubsystemTest;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.ServiceName;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


/**
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class KeyStoresTestCase extends AbstractSubsystemTest {

    public KeyStoresTestCase() {
        super(ElytronExtension.SUBSYSTEM_NAME, new ElytronExtension());
    }

    private KernelServices services = null;
    private String resources = KeyStoresTestCase.class.getResource(".").getFile();

    private ModelNode assertSuccess(ModelNode response) {
        if (!response.get(OUTCOME).asString().equals(SUCCESS)) {
            Assert.fail(response.toJSONString(false));
        }
        return response;
    }

    @Before
    public void init() throws Exception {
        services = super.createKernelServicesBuilder(new TestEnvironment()).setSubsystemXmlResource("tls-test.xml").build();
        if (!services.isSuccessfulBoot()) {
            Assert.fail(services.getBootError().toString());
        }
    }

    @Test
    public void testKeystoreService() throws Exception {
        ServiceName serviceName = Capabilities.KEY_STORE_RUNTIME_CAPABILITY.getCapabilityServiceName("FireflyKeystore");
        KeyStore keyStore = (KeyStore) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(keyStore);

        Assert.assertTrue(keyStore.containsAlias("firefly"));
        Assert.assertTrue(keyStore.isKeyEntry("firefly"));
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("firefly");
        Assert.assertEquals("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Firefly", cert.getSubjectDN().getName());
        Assert.assertEquals("firefly", keyStore.getCertificateAlias(cert));

        Certificate[] chain = keyStore.getCertificateChain("firefly");
        Assert.assertEquals("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Firefly", ((X509Certificate) chain[0]).getSubjectDN().getName());
        Assert.assertEquals("O=Root Certificate Authority, EMAILADDRESS=elytron@wildfly.org, C=UK, ST=Elytron, CN=Elytron CA", ((X509Certificate) chain[1]).getSubjectDN().getName());

        Assert.assertTrue(keyStore.containsAlias("ca"));
        Assert.assertTrue(keyStore.isCertificateEntry("ca"));
        X509Certificate certCa = (X509Certificate) keyStore.getCertificate("ca");
        Assert.assertEquals("O=Root Certificate Authority, EMAILADDRESS=elytron@wildfly.org, C=UK, ST=Elytron, CN=Elytron CA", certCa.getSubjectDN().getName());
        Assert.assertEquals("ca", keyStore.getCertificateAlias(certCa));
    }

    @Test
    public void testKeystoreCli() throws Exception {
        Files.copy(Paths.get(resources, "firefly.keystore"), Paths.get(resources, "firefly-copy.keystore"), java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        ModelNode operation = new ModelNode(); // add keystore
        operation.get(ClientConstants.OPERATION_HEADERS).get("allow-resource-service-restart").set(Boolean.TRUE);
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add("key-store","ModifiedKeyStore");
        operation.get(ClientConstants.OP).set(ClientConstants.ADD);
        operation.get(ElytronDescriptionConstants.PATH).set(resources + "/firefly-copy.keystore");
        operation.get(ElytronDescriptionConstants.TYPE).set("JKS");
        operation.get(ElytronDescriptionConstants.PASSWORD).set("Elytron");
        assertSuccess(services.executeOperation(operation));

        operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add("key-store","ModifiedKeyStore");
        operation.get(ClientConstants.OP).set(ClientConstants.READ_CHILDREN_NAMES_OPERATION);
        operation.get(ClientConstants.CHILD_TYPE).set(ElytronDescriptionConstants.ALIAS);
        List<ModelNode> nodes = assertSuccess(services.executeOperation(operation)).get(ClientConstants.RESULT).asList();
        Assert.assertEquals(2, nodes.size());

        operation = new ModelNode();
        operation.get(ClientConstants.OPERATION_HEADERS).get("allow-resource-service-restart").set(Boolean.TRUE);
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add("key-store","ModifiedKeyStore").add("alias","ca");
        operation.get(ClientConstants.OP).set(ClientConstants.REMOVE_OPERATION);
        assertSuccess(services.executeOperation(operation));

        operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add("key-store","ModifiedKeyStore");
        operation.get(ClientConstants.OP).set(ClientConstants.READ_CHILDREN_NAMES_OPERATION);
        operation.get(ClientConstants.CHILD_TYPE).set(ElytronDescriptionConstants.ALIAS);
        nodes = assertSuccess(services.executeOperation(operation)).get(ClientConstants.RESULT).asList();
        Assert.assertEquals(1, nodes.size());

        operation = new ModelNode(); // remove keystore
        operation.get(ClientConstants.OPERATION_HEADERS).get("allow-resource-service-restart").set(Boolean.TRUE);
        operation.get(ClientConstants.OP_ADDR).add("subsystem","elytron").add("key-store","ModifiedKeyStore");
        operation.get(ClientConstants.OP).set(ClientConstants.REMOVE_OPERATION);
        assertSuccess(services.executeOperation(operation));
    }

}
