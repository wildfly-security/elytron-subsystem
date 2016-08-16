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

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.jboss.as.subsystem.test.AbstractSubsystemTest;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.msc.service.ServiceName;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class TlsTestCase extends AbstractSubsystemTest {

    private final int TESTING_PORT = 18201;

    public TlsTestCase() {
        super(ElytronExtension.SUBSYSTEM_NAME, new ElytronExtension());
    }

    private KernelServices services = null;

    @Before
    public void prepare() throws Throwable {
        if (services != null) return;
        services = super.createKernelServicesBuilder(new TestEnvironment()).setSubsystemXmlResource("tls-test.xml").build();
        if (!services.isSuccessfulBoot()) {
            Assert.fail(services.getBootError().toString());
        }
    }

    @Test
    public void testSslServiceNoAuth() throws Throwable {
        SSLServerSocketFactory serverSocketFactory = getSslContext("ServerSslContextNoAuth").getServerSocketFactory();
        SSLSocketFactory clientSocketFactory = getSslContext("ClientSslContextNoAuth").getSocketFactory();

        ServerSocket listeningSocket = serverSocketFactory.createServerSocket();
        listeningSocket.bind(new InetSocketAddress("localhost", TESTING_PORT));
        SSLSocket clientSocket = (SSLSocket) clientSocketFactory.createSocket("localhost", TESTING_PORT);
        SSLSocket serverSocket = (SSLSocket) listeningSocket.accept();

        testCommunication(listeningSocket, serverSocket, clientSocket, "OU=Elytron,O=Elytron,C=CZ,ST=Elytron,CN=localhost", null);
    }

    @Test
    public void testSslServiceAuth() throws Throwable {
        SSLServerSocketFactory serverSocketFactory = getSslContext("ServerSslContextAuth").getServerSocketFactory();
        SSLSocketFactory clientSocketFactory = getSslContext("ClientSslContextAuth").getSocketFactory();

        ServerSocket listeningSocket = serverSocketFactory.createServerSocket();
        listeningSocket.bind(new InetSocketAddress("localhost", TESTING_PORT));
        SSLSocket clientSocket = (SSLSocket) clientSocketFactory.createSocket("localhost", TESTING_PORT);
        SSLSocket serverSocket = (SSLSocket) listeningSocket.accept();

        testCommunication(listeningSocket, serverSocket, clientSocket, "OU=Elytron,O=Elytron,C=CZ,ST=Elytron,CN=localhost", "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Firefly");
    }

    @Test(expected = SSLPeerUnverifiedException.class)
    public void testSslServiceAuthRequiredButNotProvided() throws Throwable {
        SSLServerSocketFactory serverSocketFactory = getSslContext("ServerSslContextAuth").getServerSocketFactory();
        SSLSocketFactory clientSocketFactory = getSslContext("ClientSslContextNoAuth").getSocketFactory();

        ServerSocket listeningSocket = serverSocketFactory.createServerSocket();
        listeningSocket.bind(new InetSocketAddress("localhost", TESTING_PORT));
        SSLSocket clientSocket = (SSLSocket) clientSocketFactory.createSocket("localhost", TESTING_PORT);
        SSLSocket serverSocket = (SSLSocket) listeningSocket.accept();

        testCommunication(listeningSocket, serverSocket, clientSocket, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Firefly", "");
    }

    private SSLContext getSslContext(String contextName) {
        ServiceName serviceName = Capabilities.SSL_CONTEXT_RUNTIME_CAPABILITY.getCapabilityServiceName(contextName);
        SSLContext sslContext = (SSLContext) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(sslContext);
        return sslContext;
    }

    private void testCommunication(ServerSocket listeningSocket, SSLSocket serverSocket, SSLSocket clientSocket, String expectedServerPrincipal, String expectedClientPrincipal) throws Throwable {

        ExecutorService serverExecutorService = Executors.newSingleThreadExecutor();
        Future<byte[]> serverFuture = serverExecutorService.submit(() -> {
            try {
                byte[] received = new byte[2];
                serverSocket.getInputStream().read(received);
                serverSocket.getOutputStream().write(new byte[]{0x56, 0x78});

                if (expectedClientPrincipal != null) {
                    Assert.assertEquals(expectedClientPrincipal, serverSocket.getSession().getPeerPrincipal().getName());
                }

                return received;
            } catch (Exception e) {
                throw new RuntimeException("Server exception", e);
            }
        });

        ExecutorService clientExecutorService = Executors.newSingleThreadExecutor();
        Future<byte[]> clientFuture = clientExecutorService.submit(() -> {
            try {
                byte[] received = new byte[2];
                clientSocket.getOutputStream().write(new byte[]{0x12, 0x34});
                clientSocket.getInputStream().read(received);

                if (expectedServerPrincipal != null) {
                    Assert.assertEquals(expectedServerPrincipal, clientSocket.getSession().getPeerPrincipal().getName());
                }

                return received;
            } catch (Exception e) {
                throw new RuntimeException("Client exception", e);
            }
        });

        try {
            Assert.assertArrayEquals(new byte[]{0x12, 0x34}, serverFuture.get());
            Assert.assertArrayEquals(new byte[]{0x56, 0x78}, clientFuture.get());
        } catch (ExecutionException e) {
            if (e.getCause() != null && e.getCause() instanceof RuntimeException && e.getCause().getCause() != null) {
                throw e.getCause().getCause(); // unpack
            } else {
                throw e;
            }
        } finally {
            serverSocket.close();
            clientSocket.close();
            listeningSocket.close();
        }
    }
}