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

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.resource.authentication.OAuth2ResourceAuthenticationToken;

import java.util.Collections;

/**
 * A class that abstracts claim matching away from {@link OAuth2ResourceAuthenticationToken}. If we can find a way
 * to construct this in the context of a SpEL expression without subclassing the expression handler, then we can use
 * this instead of packing functionality into the token.
 *
 * @see OAuth2ResourceAuthenticationToken
 */
public class OAuth2AccessTokenClaimsExpressionMethods {
	private final OAuth2AccessTokenAuthority authority;

	private static final OAuth2AccessTokenAuthority NO_AUTHORITY = new OAuth2AccessTokenAuthority(Collections.emptyMap());

	public OAuth2AccessTokenClaimsExpressionMethods(Authentication authentication) {
		this.authority =
			authentication.getAuthorities()
				.stream()
				.filter(authority -> authority instanceof OAuth2AccessTokenAuthority)
				.map(authority -> (OAuth2AccessTokenAuthority)authority)
				.findFirst()
				.orElse(NO_AUTHORITY);
	}

	public OAuth2AccessTokenClaimsExpressionMethods(OAuth2AccessTokenAuthority authority) {
		this.authority = authority;
	}

	public boolean hasClaim(String name, String value) {
		return this.authority.hasClaim(name, value);
	}

	public boolean hasClaimMatching(String name, String regex) {
		return this.authority.hasClaimMatching(name, regex);
	}

	public HasMatcher has(String name) {
		return new HasMatcher(name, this.authority);
	}

	private class HasMatcher {
		private final String name;
		private final OAuth2AccessTokenAuthority authority;

		public HasMatcher(String name, OAuth2AccessTokenAuthority authority) {
			this.name = name;
			this.authority = authority;
		}

		public boolean thatMatches(String regex) {
			return this.authority.hasClaimMatching(this.name, regex);
		}

		public boolean thatEquals(String value) {
			return this.authority.hasClaim(this.name, value);
		}
	}
}
