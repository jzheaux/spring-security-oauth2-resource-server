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
package org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver;

import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.OAuth2TokenVerifier;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderLocalKeySupport;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.security.oauth2.resourceserver.access.expression.OAuth2Expressions;
import org.springframework.security.oauth2.resourceserver.access.expression.OAuth2ResourceServerExpressions;
import org.springframework.security.oauth2.resourceserver.authentication.JwtAccessTokenAuthenticationProvider;
import org.springframework.security.oauth2.resourceserver.authentication.JwtAccessTokenVerifier;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenResolver;
import org.springframework.security.oauth2.resourceserver.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.security.Key;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

/**
 * Example configuration:
 *
 * oauth2().resourceServer()
 *     .jwt()
 *         .signature().keys("http://jwk.url")
 *
 * Or:
 *
 * oauth2().resourceServer()
 *         .jwt(auth0AccessTokenProcessor())
 *         .verifiers(customVerifier())
 *
 * @author Josh Cummings
 */
public class ResourceServerConfigurer {

	private ConfigurableBeanFactory beanFactory;

	private BearerTokenResolver resolver;
	private JwtAccessTokenFormatConfigurer jwtAccessTokenFormatConfigurer;

	public ResourceServerConfigurer(ConfigurableBeanFactory beanFactory) {
		this.beanFactory = beanFactory;
	}

	public ResourceServerConfigurer bearerTokenResolver(BearerTokenResolver resolver) {
		this.resolver = resolver;
		return this;
	}

	public NeedsSignatureJwtAccessTokenFormatConfigurer jwt() {
		if ( this.jwtAccessTokenFormatConfigurer == null ) {
			this.jwtAccessTokenFormatConfigurer = new NeedsSignatureJwtAccessTokenFormatConfigurer();
		}

		//TODO don't forget the ClassCastException risk inherent in this design
		return (NeedsSignatureJwtAccessTokenFormatConfigurer) this.jwtAccessTokenFormatConfigurer;
	}

	public JwtAccessTokenFormatConfigurer jwt(JwtDecoder decoder) {
		if ( this.jwtAccessTokenFormatConfigurer == null ) {
			this.jwtAccessTokenFormatConfigurer = new JwtAccessTokenFormatConfigurer(decoder);
		}


		return this.jwtAccessTokenFormatConfigurer;
	}

	public class JwtAccessTokenFormatConfigurer {
		protected JwtDecoderConfigurer jwtDecoder = new JwtDecoderConfigurer();
		private Collection<OAuth2TokenVerifier<Jwt>> verifiers = new ArrayList<>();

		public JwtAccessTokenFormatConfigurer() {}

		public JwtAccessTokenFormatConfigurer(JwtDecoder decoder) {
			this.jwtDecoder.decoder(decoder);
		}

		public JwtAccessTokenFormatConfigurer verifiers(OAuth2TokenVerifier<Jwt>... verifiers) {
			this.verifiers = Arrays.asList(verifiers);
			return this;
		}

		public ResourceServerConfigurer and() {
			return ResourceServerConfigurer.this;
		}
	}

	public class NeedsSignatureJwtAccessTokenFormatConfigurer
		extends JwtAccessTokenFormatConfigurer {

		public SignatureVerificationConfigurer signature() {
			return new SignatureVerificationConfigurer(this);
		}
	}

	public class SignatureVerificationConfigurer {
		private JwtAccessTokenFormatConfigurer parent;

		public SignatureVerificationConfigurer(JwtAccessTokenFormatConfigurer parent) {
			this.parent = parent;
		}

		public JwtAccessTokenFormatConfigurer keys(String uri) {
			this.parent.jwtDecoder.decoder(new NimbusJwtDecoderJwkSupport(uri));
			return this.parent;
		}

		public JwtAccessTokenFormatConfigurer keys(Map<String, Key> keys) {
			this.parent.jwtDecoder.decoder(new NimbusJwtDecoderLocalKeySupport(keys));
			return this.parent;
		}

		public JwtAccessTokenFormatConfigurer key(String keyId, PublicKey key) {
			this.parent.jwtDecoder.decoder(new NimbusJwtDecoderLocalKeySupport(keyId, key));
			return this.parent;
		}
	}

	public class JwtDecoderConfigurer {
		private JwtDecoder jwtDecoder;

		public JwtDecoderConfigurer decoder(JwtDecoder decoder) {
			this.jwtDecoder = decoder;
			return this;
		}

		public JwtDecoder decoder() {
			return this.jwtDecoder;
		}
	}

	public void apply(HttpSecurity http) throws Exception {
		http
				.addFilterAfter(oauthResourceAuthenticationFilter(),
						BasicAuthenticationFilter.class)
				.sessionManagement()
						.sessionCreationPolicy(SessionCreationPolicy.NEVER).and()
				.exceptionHandling()
						.accessDeniedHandler(bearerTokenAccessDeniedHandler())
						.authenticationEntryPoint(bearerTokenAuthenticationEntryPoint()).and()
				.authorizeRequests()
						.anyRequest().authenticated().and()
						.csrf().disable();

		//TODO find better way to register this; the other configurers don't appear to do it this way
		if ( !this.beanFactory.containsBean("oauth2") ) {
			this.beanFactory.registerSingleton("oauth2", oauth2());
		}
	}

	private OAuth2Expressions oauth2() {
		return new OAuth2ResourceServerExpressions();
	}


	private BearerTokenAuthenticationFilter oauthResourceAuthenticationFilter() {
		BearerTokenAuthenticationFilter filter =
			new BearerTokenAuthenticationFilter(authenticationManager());

		if ( this.resolver != null ) {
			filter.setBearerTokenResolver(this.resolver);
		}

		return filter;
	}

	private AuthenticationManager authenticationManager() {
		return new ProviderManager(
			Arrays.asList(oauthResourceAuthenticationProvider()));
	}

	private AuthenticationProvider oauthResourceAuthenticationProvider() {
		JwtAccessTokenVerifier verifier =
				this.jwtAccessTokenFormatConfigurer.verifiers.isEmpty() ?
						new JwtAccessTokenVerifier() :
						new JwtAccessTokenVerifier(this.jwtAccessTokenFormatConfigurer.verifiers.iterator().next());

		JwtAccessTokenAuthenticationProvider provider =
			new JwtAccessTokenAuthenticationProvider(
					this.jwtAccessTokenFormatConfigurer.jwtDecoder.decoder(),
					verifier);

		return provider;
	}

	private AuthenticationEntryPoint bearerTokenAuthenticationEntryPoint() {
		return new BearerTokenAuthenticationEntryPoint();
	}

	private AccessDeniedHandler bearerTokenAccessDeniedHandler() {
		return new BearerTokenAccessDeniedHandler();
	}
}
