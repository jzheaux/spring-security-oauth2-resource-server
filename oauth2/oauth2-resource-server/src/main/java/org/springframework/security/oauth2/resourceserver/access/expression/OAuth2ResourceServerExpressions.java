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
package org.springframework.security.oauth2.resourceserver.access.expression;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ScopeClaimAccessor;
import org.springframework.security.oauth2.jwt.JwtClaimAccessor;
import org.springframework.security.oauth2.resourceserver.authentication.AbstractOAuth2AccessTokenAuthenticationToken;

import java.net.URL;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

/**
 * A class for evaluating SpEL expressions based on OAuth2 Authentication tokens.
 *
 * @author Josh Cummings
 * @since 5.1
 * @see AbstractOAuth2AccessTokenAuthenticationToken
 */
public class OAuth2ResourceServerExpressions implements OAuth2Expressions, JwtExpressions {
	private String scopeClaimName;

	public OAuth2ResourceServerExpressions() {
		this.scopeClaimName = "scope";
	}

	public OAuth2ResourceServerExpressions(String scopeClaimName) {
		this.scopeClaimName = scopeClaimName;
	}

	@Override
	public Object attribute(Authentication authentication, String name) {
		return attributes(authentication).get(name);
	}

	@Override
	public Collection<String> scopes(Authentication authentication) {
		return scope(authentication).getScope(this.scopeClaimName);
	}

	@Override
	public boolean hasScope(Authentication authentication, String scope) {
		return Optional.ofNullable(scopes(authentication))
					.map(auth -> auth.contains(scope))
					.orElse(false);
	}

	@Override
	public boolean hasAnyScope(Authentication authentication, String... scopes) {
		return Optional.ofNullable(scopes(authentication))
					.map(auth -> {
						auth.retainAll(Arrays.asList(scopes));
						return !auth.isEmpty();
					})
					.orElse(false);
	}

	@Override
	public boolean hasAllScopes(Authentication authentication, String... scopes) {
		return Optional.ofNullable(scopes(authentication))
					.map(auth -> auth.containsAll(Arrays.asList(scopes)))
					.orElse(false);
	}

	@Override
	public Collection<String> audience(Authentication authentication) {
		return jwt(authentication).getAudience();
	}

	@Override
	public Instant expiresAt(Authentication authentication) {
		return jwt(authentication).getExpiresAt();
	}

	@Override
	public String id(Authentication authentication) {
		return jwt(authentication).getId();
	}

	@Override
	public Instant issuedAt(Authentication authentication) {
		return jwt(authentication).getIssuedAt();
	}

	@Override
	public URL issuer(Authentication authentication) {
		return jwt(authentication).getIssuer();
	}

	@Override
	public Instant notBefore(Authentication authentication) {
		return jwt(authentication).getNotBefore();
	}

	@Override
	public String subject(Authentication authentication) {
		return jwt(authentication).getSubject();
	}

	private ScopeClaimAccessor scope(Authentication authentication) {
		return () -> attributes(authentication);
	}

	private JwtClaimAccessor jwt(Authentication authentication) {
		return () -> attributes(authentication);
	}

	private Map<String, Object> attributes(Authentication authentication) {
		return Optional.ofNullable(authentication)
				.filter(auth -> auth instanceof AbstractOAuth2AccessTokenAuthenticationToken)
				.map(auth -> (AbstractOAuth2AccessTokenAuthenticationToken) auth)
				.map(auth -> auth.getTokenAttributes())
				.orElse(Collections.emptyMap());
	}
}
