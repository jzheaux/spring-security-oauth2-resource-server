/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.boot.security.oauth2.resourceserver;

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver.ResourceServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.KeyProvider;
import org.springframework.security.oauth2.resourceserver.authentication.JwtClaimValidator;
import org.springframework.util.StringUtils;

import java.security.PublicKey;

import static org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver.ResourceServerConfigurer.UrlConfigurer.url;

@Configuration
public class ResourceServerAutoConfiguration {

	@Bean
	@ConfigurationProperties(prefix = "spring.security.oauth2.resourceserver")
	@ConditionalOnMissingBean
	public ResourceServerProperties properties() {
		return new ResourceServerProperties();
	}

	@Bean
	@ConditionalOnClass(WebSecurityConfigurerAdapter.class)
	@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
	@Order
	public WebSecurityConfigurerAdapter securityConfig() {
		return new WebSecurityConfigurerAdapter() {
			@Override
			protected void configure(HttpSecurity http) throws Exception {
				ResourceServerConfigurer<HttpSecurity> resourceServer =
						resourceServer(http);

				IssuerDetails details = properties().getIssuer();

				if ( StringUtils.hasText(details.getJwkSetUri()) ) {
					String uri = details.getJwkSetUri();
					resourceServer.jwt().signature().keys(url(uri));
				} else if ( details.getKeys().getSignature() != null ) {
					KeyProvider<PublicKey> signature = details.getKeys().getSignature();
					resourceServer.jwt().signature().keys(signature);
				}

				if ( StringUtils.hasText(details.getBaseUri()) ) {
					resourceServer.jwt().validators(
							new JwtClaimValidator(
									JwtClaimNames.ISS,
									details.getBaseUri())
					);
				}
			}

			protected ResourceServerConfigurer<HttpSecurity> resourceServer(HttpSecurity http) throws Exception {
				return http.apply(new ResourceServerConfigurer<>());
			}
		};
	}
}
