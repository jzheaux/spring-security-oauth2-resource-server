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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver.ResourceServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.resourceserver.access.expression.OAuth2Expressions;
import org.springframework.security.oauth2.resourceserver.access.expression.OAuth2ResourceServerExpressions;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver.ResourceServerConfigurer.UrlConfigurer.url;

/**
 * @author Josh Cummings
 */
@SpringBootApplication
public class KeycloakApplication {

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	class WebSecurityConfig extends WebSecurityConfigurerAdapter {
		@Value("${spring.boot.oauth2.resourceserver.keycloak.certsEndpoint}") String certsEndpoint;

		@Override
		protected void configure(HttpSecurity http) throws Exception {

			resourceServer(http)
					.jwt()
							.signature()
								.keys(url(this.certsEndpoint));
		}

		protected ResourceServerConfigurer resourceServer(HttpSecurity http) throws Exception {
			return http.apply(new ResourceServerConfigurer());
		}
	}

	@Bean
	public OAuth2Expressions oauth2() {
		return new OAuth2ResourceServerExpressions() {
			@Override
			public Collection<String> scopes(Authentication authentication) {
				Map<String, Object> attributes = super.attributes(authentication);

				return Optional.ofNullable(attributes.get("realm_access"))
						.map(realmAccess -> (Map<String, Object>) realmAccess)
						.map(realmAccess -> realmAccess.get("roles"))
						.map(roles -> (List<String>) roles)
						.orElse(Collections.emptyList());
			}
		};
	}

	public static void main(String[] args) {
		SpringApplication.run(KeycloakApplication.class, args);
	}
}
