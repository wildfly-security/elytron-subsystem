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
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.jboss.as.subsystem.test.AbstractSubsystemTest;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.msc.service.ServiceName;
import org.junit.Assert;
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

    @Test
    public void testSslService() throws Exception {
        services = super.createKernelServicesBuilder(new TestEnvironment()).setSubsystemXmlResource("tls-test.xml").build();
        if (!services.isSuccessfulBoot()) {
            Assert.fail(services.getBootError().toString());
        }

        ServiceName serverServiceName = Capabilities.SSL_CONTEXT_RUNTIME_CAPABILITY.getCapabilityServiceName("ServerSslContext");
        SSLContext serverSslContext = (SSLContext) services.getContainer().getService(serverServiceName).getValue();
        Assert.assertNotNull(serverSslContext);
        SSLServerSocketFactory serverSocketFactory = serverSslContext.getServerSocketFactory();

        SSLSocketFactory clientSocketFactory = getClientFactory();

        ServerSocket listeningSocket = serverSocketFactory.createServerSocket();
        listeningSocket.bind(new InetSocketAddress("localhost", TESTING_PORT));

        SSLSocket clientSocket = (SSLSocket) clientSocketFactory.createSocket("localhost", TESTING_PORT);
        clientSocket.setUseClientMode(true);
        SSLSocket serverSocket = (SSLSocket) listeningSocket.accept();
        serverSocket.setUseClientMode(false);

        ExecutorService clientExecutorService = Executors.newSingleThreadExecutor();
        Future<byte[]> clientFuture = clientExecutorService.submit(() -> {
            try {
                byte[] received = new byte[2];
                clientSocket.getOutputStream().write(new byte[]{0x12, 0x34});
                serverSocket.getInputStream().read(received);
                return received;
            } catch (Exception e) {
                throw new RuntimeException("Client exception", e);
            }
        });

        ExecutorService serverExecutorService = Executors.newSingleThreadExecutor();
        Future<byte[]> serverFuture = serverExecutorService.submit(() -> {
            try {
                byte[] received = new byte[2];
                serverSocket.getInputStream().read(received);
                clientSocket.getOutputStream().write(new byte[]{0x56, 0x78});
                return received;
            } catch (Exception e) {
                throw new RuntimeException("Server exception", e);
            }
        });

        Assert.assertArrayEquals(new byte[]{0x12, 0x34}, serverFuture.get());
        Assert.assertArrayEquals(new byte[]{0x56, 0x78}, clientFuture.get());

        serverSocket.close();
        listeningSocket.close();
        clientSocket.close();
    }

    // TODO replace by factory from elytron when will be SSL client side available in Elytron
    private SSLSocketFactory getClientFactory() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
        };
        SSLContext clientContext = SSLContext.getInstance("TLS");
        clientContext.init(null, trustAllCerts, null);
        return clientContext.getSocketFactory();
    }
}