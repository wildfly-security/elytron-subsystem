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

import java.util.function.Supplier;

import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;

/**
 * A very trivial {@link Service} implementation where creation of the value type can easily be
 * wrapped using a {@link Supplier}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class TrivialService<T> implements Service<T> {

    private final Supplier<T> valueSupplier;

    private volatile T value;

    TrivialService(Supplier<T> valueSupplier) {
        this.valueSupplier = valueSupplier;
    }

    @Override
    public void start(StartContext context) throws StartException {
        value = valueSupplier.get();
    }

    @Override
    public void stop(StopContext context) {
        value = null;
    }

    @Override
    public T getValue() throws IllegalStateException, IllegalArgumentException {
        return value;
    }
}
