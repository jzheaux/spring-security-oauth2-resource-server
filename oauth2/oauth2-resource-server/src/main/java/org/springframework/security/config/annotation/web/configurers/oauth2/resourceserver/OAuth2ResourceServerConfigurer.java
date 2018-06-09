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

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2TokenVerifier;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenResolver;

/**
 * Example configuration:
 *
 * oauth2().resourceServer().accessToken()
 *     .formats()
 *         .jwt().and()
 *     .verifiers()
 *         .signature().keys("http://jwk.url")
 *
 * Or:
 *
 * oauth2().resourceServer().accessToken()
 *     .formats()
 *         .jwt()
 *             .processor(auth0AccessTokenProcessor())
 *             .and()
 *         .opaque()
 *             .processor(auth0AccessTokenProcessor())
 *             .and()
 *         .and()
 *     .verifiers()
 *          .addVerifier(claims -> {
 *              if ( claims.get("iss") == null ) {
 *                  throw new OAuth2AuthenticationException(...);
 *              }
 *          })
 *
 * @author Josh Cummings
 */
public class OAuth2ResourceServerConfigurer<B extends HttpSecurityBuilder<B>> extends
		AbstractHttpConfigurer<OAuth2ResourceServerConfigurer<B>, B> {

	private AccessTokenFormatsConfigurer accessTokenFormatsConfigurer;
	private AccessTokenVerifiersConfigurer accessTokenVerifiersConfigurer;

	public OAuth2ResourceServerConfigurer<B> bearerTokenResolver(BearerTokenResolver resolver) {
		return this;
	}

	public AccessTokenConfigurer accessToken(OAuth2TokenVerifier... verifiers) {
		return new AccessTokenConfigurer();
	}

	public class AccessTokenConfigurer {
		public AccessTokenVerifiersConfigurer verifiers() {
			return new AccessTokenVerifiersConfigurer();
		}

		public AccessTokenFormatsConfigurer formats() {
			return new AccessTokenFormatsConfigurer();
		}

		public OAuth2ResourceServerConfigurer<B> and() {
			return OAuth2ResourceServerConfigurer.this;
		}
	}

	public class AccessTokenVerifiersConfigurer {
		public SignatureVerificationConfigurer signature() {
			return new SignatureVerificationConfigurer();
		}

		public EncryptionVerificationConfigurer encryption() {
			return new EncryptionVerificationConfigurer();
		}

		public AccessTokenVerifiersConfigurer addVerifier(OAuth2TokenVerifier verifier) {
			return this;
		}

		public AccessTokenConfigurer and() {
			return null;
		}
	}

	public class SignatureVerificationConfigurer {
		public SignatureVerificationConfigurer keys(String uri) {
			return this;
		}

		public AccessTokenVerifiersConfigurer and() {
			return OAuth2ResourceServerConfigurer.this.accessTokenVerifiersConfigurer;
		}
	}

	public class EncryptionVerificationConfigurer {
		public EncryptionVerificationConfigurer keys(String uri) {
			return this;
		}

		public AccessTokenVerifiersConfigurer and() {
			return OAuth2ResourceServerConfigurer.this.accessTokenVerifiersConfigurer;
		}
	}

	public class AccessTokenFormatsConfigurer {
		public OpaqueAccessTokenFormatConfigurer opaque() {
			return new OpaqueAccessTokenFormatConfigurer();
		}

		public JwtAccessTokenFormatConfigurer jwt() {
			return new JwtAccessTokenFormatConfigurer();
		}

		public AccessTokenConfigurer and() {
			return null;
		}
	}

	public class OpaqueAccessTokenFormatConfigurer {
		public OpaqueAccessTokenFormatConfigurer processor
				(OAuth2AccessTokenProcessor<? extends AbstractOAuth2Token> processor) {
			return this;
		}

		public AccessTokenFormatsConfigurer and() {
			return OAuth2ResourceServerConfigurer.this.accessTokenFormatsConfigurer;
		}
	}

	public class JwtAccessTokenFormatConfigurer {
		public JwtAccessTokenFormatConfigurer processor
				(OAuth2AccessTokenProcessor<Jwt> processor) {
			return this;
		}

		public AccessTokenFormatsConfigurer and() {
			return OAuth2ResourceServerConfigurer.this.accessTokenFormatsConfigurer;
		}
	}

	private interface OAuth2AccessTokenProcessor<T extends AbstractOAuth2Token> {
		T process(String token);
	}
}
