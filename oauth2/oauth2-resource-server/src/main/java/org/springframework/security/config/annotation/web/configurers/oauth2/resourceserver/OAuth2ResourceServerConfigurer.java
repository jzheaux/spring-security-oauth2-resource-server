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
import org.springframework.security.oauth2.core.OAuth2TokenVerifier;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenResolver;

public class OAuth2ResourceServerConfigurer<B extends HttpSecurityBuilder<B>> extends
		AbstractHttpConfigurer<OAuth2ResourceServerConfigurer<B>, B> {

	public OAuth2ResourceServerConfigurer<B> bearerTokenResolver(BearerTokenResolver resolver) {
		return this;
	}

	public OAuth2ResourceServerConfigurer<B> accessTokenVerifier(OAuth2TokenVerifier... verifiers) {
		return this;
	}

	public JwtConfigurer jwt() {
		return null;
	}

	public class JwtConfigurer {
		public JwtConfigurer jwkSetUrl(String location) {
			return this;
		}

		public OAuth2ResourceServerConfigurer<B> and() {
			return OAuth2ResourceServerConfigurer.this;
		}
	}
}
