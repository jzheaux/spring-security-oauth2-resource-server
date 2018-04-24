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

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.resourceserver.access.expression.OAuth2Expressions;
import org.springframework.security.oauth2.resourceserver.access.expression.OAuth2ResourceServerExpressions;
import org.springframework.security.oauth2.resourceserver.authentication.JwtAccessTokenAuthenticationProvider;
import org.springframework.security.oauth2.resourceserver.authentication.JwtAccessTokenVerifier;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;

/**
 * @author Josh Cummings
 */
@SpringBootApplication
public class MessagesApplication {

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	class WebSecurityConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.addFilterAfter(
							oauthResourceAuthenticationFilter(),
							BasicAuthenticationFilter.class)
					.exceptionHandling()
					.authenticationEntryPoint(restAuthenticationEntryPoint()).and()
					.authorizeRequests()
					.anyRequest().authenticated().and()
					.csrf().disable();
		}
	}

	@Bean
	public OAuth2Expressions oauth2() {
		return new OAuth2ResourceServerExpressions();
	}

	// @Bean -- We don't want this to get wired by Spring Boot as a servlet-level filter
	// Is there a more clever way to do this?
	BearerTokenAuthenticationFilter oauthResourceAuthenticationFilter() {
		BearerTokenAuthenticationFilter filter =
			new BearerTokenAuthenticationFilter(authenticationManager());

		return filter;
	}

	@Bean
	AuthenticationManager authenticationManager() {
		return new ProviderManager(
			Arrays.asList(oauthResourceAuthenticationProvider())
		);
	}

	@Bean
	AuthenticationProvider oauthResourceAuthenticationProvider() {
		JwtAccessTokenAuthenticationProvider provider =
			new JwtAccessTokenAuthenticationProvider(jwtDecoder(), new JwtAccessTokenVerifier());

		return provider;
	}

	@Bean
	JwtDecoder jwtDecoder() {
		return new NimbusJwtDecoder(keyPair().getPublic());
	}

	@Bean
	AuthenticationEntryPoint restAuthenticationEntryPoint() {
		return new BearerTokenAuthenticationEntryPoint();
	}

	@Bean
	KeyPair keyPair() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			return generator.generateKeyPair();
		} catch ( Exception e ) {
			throw new IllegalArgumentException(e);
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(MessagesApplication.class, args);
	}
}
