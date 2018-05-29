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

package org.springframework.boot.autoconfigure.security.oauth2.resourceserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
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
@EnableConfigurationProperties(OAuth2ResourceServerProperties.class)
public class OAuth2ResourceServerWebSecurityConfiguraion {
	private final OAuth2ResourceServerProperties properties;

	OAuth2ResourceServerWebSecurityConfiguraion(OAuth2ResourceServerProperties properties) {
		this.properties = properties;
	}

	@Configuration
	@ConditionalOnMissingBean(WebSecurityConfigurerAdapter.class)
	static class OAuth2WebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
		@Autowired
		OAuth2ResourceServerProperties properties;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests().anyRequest().authenticated();

			ResourceServerConfigurer<HttpSecurity> resourceServer =
					resourceServer(http);

			OAuth2ResourceServerProperties.IssuerDetails details = this.properties.getIssuer();

			if ( StringUtils.hasText(details.getJwkSetUri()) ) {
				String uri = details.getJwkSetUri();
				resourceServer.jwt().signature().keys(url(uri));
			} else if ( details.getKeys().getSignature() != null ) {
				KeyProvider<PublicKey> signature = details.getKeys().getSignature();
				resourceServer.jwt().signature().keys(signature);
			}

			if ( StringUtils.hasText(details.getBaseUri()) ) {
				resourceServer.jwt().validator(
						new JwtClaimValidator(
								JwtClaimNames.ISS,
								details.getBaseUri())
				);
			}
		}

		protected ResourceServerConfigurer<HttpSecurity> resourceServer(HttpSecurity http) throws Exception {
			return http.apply(new ResourceServerConfigurer<>());
		}
	}
}
