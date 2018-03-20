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
package org.springframework.security.samples.oauth2.rs.auth0;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.bearer.OAuth2AccessTokenAuthority;
import org.springframework.security.oauth2.jwt.AccessTokenJwtVerifier;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.resource.authentication.JwtEncodedOAuth2AccessTokenAuthenticationProvider;
import org.springframework.security.oauth2.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.InputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

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

	// @Bean -- We don't want this to get wired by Spring Boot as a servlet-level filter
	// Is there a more clever way to do this?
	BearerTokenAuthenticationFilter oauthResourceAuthenticationFilter() {
		BearerTokenAuthenticationFilter filter =
			new BearerTokenAuthenticationFilter(authenticationManager());
		//filter.setAuthenticationManager(authenticationManager());

		// We don't want to redirect in a REST call, we just want to proceed to the resource
		//filter.setAuthenticationSuccessHandler((req, resp, auth) -> {});

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
		JwtEncodedOAuth2AccessTokenAuthenticationProvider provider =
			new JwtEncodedOAuth2AccessTokenAuthenticationProvider(jwtDecoder(), new AccessTokenJwtVerifier());

		provider.setAuthoritiesMapper(authorities -> {
			Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

			authorities.forEach(authority -> {
				if (authority instanceof OAuth2AccessTokenAuthority) {
					Optional.ofNullable(((OAuth2AccessTokenAuthority) authority).getClaim("scope"))
						.ifPresent(scope ->
							Stream.of(scope.toString().split(" "))
								.map(SimpleGrantedAuthority::new)
								.forEach(mappedAuthorities::add));
				}
				mappedAuthorities.add(authority);
			});

			return mappedAuthorities;
		});

		return provider;
	}

	@Bean
	JwtDecoder jwtDecoder() {
		InputStream is = this.getClass().getClassLoader().getResourceAsStream("id_rsa.pub");
		RSAKeyProvider provider = new PemParsingPublicKeyOnlyRSAKeyProvider(is);
		JWTVerifier verifier = JWT.require(Algorithm.RSA256(provider)).withIssuer("rob").build();
		return new Auth0JwtDecoderJwkSupport(verifier);
	}

	@Bean
	AuthenticationEntryPoint restAuthenticationEntryPoint() {
		return new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);
	}

	public static void main(String[] args) {
		SpringApplication.run(MessagesApplication.class, args);
	}
}
