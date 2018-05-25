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

package sample;

import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimAccessor;
import org.springframework.security.oauth2.resourceserver.access.expression.OAuth2Expressions;
import org.springframework.security.oauth2.resourceserver.access.expression.OAuth2ResourceServerExpressions;
import org.springframework.security.oauth2.resourceserver.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;
import java.util.stream.Collectors;

@EnableGlobalMethodSecurity(prePostEnabled = true)
@ComponentScan(basePackageClasses = KeycloakSecurityComponents.class)
public class KeycloakAdapterSecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

	@Autowired
	public void configureGlboal(AuthenticationManagerBuilder auth) {
		auth.authenticationProvider(keycloakAuthenticationProvider());
	}

	@Override
	protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
		return new NullAuthenticatedSessionStrategy();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		super.configure(http);

		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
		http.exceptionHandling().accessDeniedHandler(new BearerTokenAccessDeniedHandler());

		http.authorizeRequests().anyRequest().authenticated();
	}

	@Bean
	public KeycloakConfigResolver keycloakConfigResolver() {
		return new KeycloakSpringBootConfigResolver();
	}

	@Bean
	public OAuth2Expressions oauth2() {
		return new OAuth2ResourceServerExpressions() {
			@Override
			public Collection<String> scopes(Authentication authentication) {
				return keycloak(authentication)
						.map(Authentication::getAuthorities)
						.orElse(Collections.emptyList())
						.stream()
						.map(GrantedAuthority::getAuthority)
						.collect(Collectors.toList());
			}

			@Override
			protected JwtClaimAccessor jwt(Authentication authentication) {
				return keycloak(authentication)
						.map(KeycloakAdapterAuthenticationClaimAccessor::new)
						.map(access -> (JwtClaimAccessor) access)
						.orElse(() -> Collections.emptyMap());
			}

			private Optional<KeycloakAuthenticationToken> keycloak(Authentication authentication) {
				return Optional.ofNullable(authentication)
						.filter(a -> a instanceof KeycloakAuthenticationToken)
						.map(a -> (KeycloakAuthenticationToken) a);
			}
		};
	}
}
