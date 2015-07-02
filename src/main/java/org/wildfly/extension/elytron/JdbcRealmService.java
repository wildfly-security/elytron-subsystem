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

import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.security.auth.provider.jdbc.JdbcSecurityRealm;
import org.wildfly.security.auth.provider.jdbc.KeyMapper;
import org.wildfly.security.auth.spi.SecurityRealm;

import javax.sql.DataSource;
import java.util.List;

/**
 * A {@link Service} implementation responsible for supplying a {@link SecurityRealm} backed by a database.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class JdbcRealmService implements Service<SecurityRealm> {

    private final String authenticationQuery;
    private final List<KeyMapper> keyMappers;

    private final InjectedValue<DataSource> dataSourceInjectedValue = new InjectedValue<DataSource>();

    private volatile SecurityRealm securityRealm;

    JdbcRealmService(String authenticationQuery, List<KeyMapper> keyMappers) {
        this.authenticationQuery = authenticationQuery;
        this.keyMappers = keyMappers;
    }

    @Override
    public void start(StartContext startContext) throws StartException {
        DataSource dataSource = getDataSourceInjectedValue().getValue();

        securityRealm = JdbcSecurityRealm.builder()
                .authenticationQuery(this.authenticationQuery)
                    .from(dataSource)
                    .withMapper(this.keyMappers.toArray(new KeyMapper[this.keyMappers.size()])).build();
    }

    @Override
    public void stop(StopContext stopContext) {
        securityRealm = null;
    }

    @Override
    public SecurityRealm getValue() throws IllegalStateException, IllegalArgumentException {
        return securityRealm;
    }

    public InjectedValue<DataSource> getDataSourceInjectedValue() {
        return this.dataSourceInjectedValue;
    }
}