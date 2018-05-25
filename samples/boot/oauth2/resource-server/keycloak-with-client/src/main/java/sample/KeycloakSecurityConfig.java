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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver.ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.web.client.RestTemplate;

import static org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver.ResourceServerConfigurer.UrlConfigurer.url;
import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

/**
 * @author Thomas Darimont
 * @author Josh Cummings
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class KeycloakSecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${kc.realm}") String realm;
	@Value("${spring.security.oauth2.resourceserver.provider.keycloak.jwk-set-uri}") String jwkSetUri;

	@Autowired
	OAuth2ClientProperties oAuth2ClientProperties;

	@Bean
	SimpleAuthorityMapper authoritiesMapper() {
		SimpleAuthorityMapper authoritiesMapper = new SimpleAuthorityMapper();
		authoritiesMapper.setConvertToUpperCase(true);

		return authoritiesMapper;
	}

	@Bean
	KeycloakOAuth2UserService keycloakOidcUserService(OAuth2ClientProperties oauth2ClientProperties) {
		String jwkSetUri = oauth2ClientProperties.getProvider().get("keycloak").getJwkSetUri();
		return new KeycloakOAuth2UserService(authoritiesMapper(), new NimbusJwtDecoderJwkSupport(jwkSetUri));
	}

	@Bean
	KeycloakLogoutHandler keycloakLogoutHandler() {
		return new KeycloakLogoutHandler(new RestTemplate());
	}

	@Bean
	KeycloakAuthoritiesExtractor keycloakOAuth2TokenAuthoritiesExtractor() {
		KeycloakAuthoritiesExtractor extractor = new KeycloakAuthoritiesExtractor();

		extractor.setAuthoritiesMapper(authoritiesMapper());

		return extractor;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.apply(new ResourceServerConfigurer<>())
				.jwt()
					.signature().keys(url(jwkSetUri))
					.authoritiesExtractor(keycloakOAuth2TokenAuthoritiesExtractor())
					.and()
				.and()
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
				.and()
			.authorizeRequests()
				.anyRequest().permitAll()
				.and()
			.logout()
				.addLogoutHandler(keycloakLogoutHandler())
				.and()
			.oauth2Login()
				.userInfoEndpoint()
					.oidcUserService(keycloakOidcUserService(oAuth2ClientProperties))
					.and()
				.loginPage(DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/" + realm);
		// @formatter:on
	}
}
