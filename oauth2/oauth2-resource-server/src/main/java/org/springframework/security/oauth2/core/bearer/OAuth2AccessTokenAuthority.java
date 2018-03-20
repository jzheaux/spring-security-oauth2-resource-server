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
package org.springframework.security.oauth2.core.bearer;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.resourceserver.authentication.OAuth2ResourceAuthenticationToken;

import java.util.Map;
import java.util.Optional;

/**
 * A {@link GrantedAuthority} that may be associated to an {@link OAuth2ResourceAuthenticationToken}.
 *
 * @author Josh Cummings
 * @since 5.1
 * @see OAuth2ResourceAuthenticationToken
 */
public class OAuth2AccessTokenAuthority implements GrantedAuthority {
	private final Map<String, Object> claims;
	private final String authority;

	/**
	 *
	 * @param claims - A set of claims as derived from, say a JWT or from consulting an authorization server
	 *
	 */
	public OAuth2AccessTokenAuthority(Map<String, Object> claims) {
		this.authority = "ROLE_USER";
		this.claims = claims;
	}

	/**
	 * Check for the given claim by {@param name} and see if it's value matches the given {@param regex}
	 * @param name
	 * @param regex
	 * @return
	 */
	public boolean hasClaimMatching(String name, String regex) {
		return Optional
				.ofNullable(this.claims.get(name))
				.map(value -> value.toString())
				.filter(value -> value.matches(regex))
				.isPresent();
	}

	/**
	 * Check for the given claim by {@param name} and {@param value}
	 * @param name
	 * @param value
	 * @return
	 */
	public boolean hasClaim(String name, Object value) {
		return Optional
				.ofNullable(this.claims.get(name))
				.filter(v -> v.equals(value))
				.isPresent();
	}

	/**
	 * Retrieve a claim by its {@see name}
	 * @param name
	 * @return
	 */
	public Object getClaim(String name) {
		return this.claims.get(name);
	}

	@Override
	public String getAuthority() {
		return this.authority;
	}
}
