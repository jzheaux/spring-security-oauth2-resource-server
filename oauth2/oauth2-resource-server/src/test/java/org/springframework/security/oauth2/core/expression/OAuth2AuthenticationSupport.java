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
package org.springframework.security.oauth2.core.expression;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.resourceserver.authentication.AbstractOAuth2AccessTokenAuthenticationToken;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Josh Cummings
 */
public class OAuth2AuthenticationSupport {
	private Map<String, Object> attributes = new HashMap<>();
	private String token = "token";

	public OAuth2AuthenticationSupport attribute(String name, Object value) {
		this.attributes.put(name, value);
		return this;
	}

	public OAuth2AuthenticationSupport token(String token) {
		this.token = token;
		return this;
	}

	public Authentication authenticate() {
		Authentication authentication =
				new AbstractOAuth2AccessTokenAuthenticationToken(Collections.emptyList()) {
					@Override
					public Map<String, Object> getTokenAttributes() {
						return OAuth2AuthenticationSupport.this.attributes;
					}
				};

		authentication.setAuthenticated(true);

		SecurityContextHolder.getContext().setAuthentication(authentication);

		return authentication;
	}

	public void clear() {
		SecurityContextHolder.clearContext();
	}
}
