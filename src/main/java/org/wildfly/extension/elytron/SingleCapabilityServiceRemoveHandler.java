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

import javax.xml.ws.Service;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.ServiceRemoveStepHandler;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.msc.service.ServiceName;

/**
 * An {@link OperationStepHandler} for removing a single service based on it's capability.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class SingleCapabilityServiceRemoveHandler<T> extends ServiceRemoveStepHandler {

    private final RuntimeCapability<?> runtimeCapability;
    private final Class<T> serviceType;

    /**
     * Construct an {@link OperationStepHandler} for removing a single service based on it's capability.
     *
     * @param addOperation
     * @param unavailableCapabilities
     */
    SingleCapabilityServiceRemoveHandler(AbstractAddStepHandler addOperation, RuntimeCapability<?> runtimeCapability, Class<T> serviceType) {
        super(addOperation, runtimeCapability);
        this.runtimeCapability = runtimeCapability;
        this.serviceType = serviceType;
    }

    /**
     * Create the name of the {@link Service} to be removed using the previously provided {@link RuntimeCapability} and the type
     * of the service.
     */
    @Override
    protected ServiceName serviceName(String name) {
        RuntimeCapability<?> dynamicCapability = runtimeCapability.fromBaseCapability(name);
        return dynamicCapability.getCapabilityServiceName(serviceType);
    }

}
