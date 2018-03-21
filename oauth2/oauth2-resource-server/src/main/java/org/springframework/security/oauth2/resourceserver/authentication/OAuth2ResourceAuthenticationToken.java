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
package org.springframework.security.oauth2.resourceserver.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.core.bearer.OAuth2AccessTokenAuthority;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Collections;

/**
 * An {@link org.springframework.security.core.Authentication} implementation that is
 * designed for the presentation of OAuth2 Bearer tokens.
 *
 * @author Josh Cummings
 * @since 5.1
 *
 * @see org.springframework.security.core.Authentication
 */
public class OAuth2ResourceAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private static final OAuth2AccessTokenAuthority NO_AUTHORITY = new OAuth2AccessTokenAuthority(Collections.emptyMap());

	private final String token;

	private OAuth2AccessTokenAuthority authority;

	/**
	 * @param token - An OAuth2 Bearer Token
	 */
	public OAuth2ResourceAuthenticationToken(String token) {
		super(Collections.emptyList());

		Assert.hasText(token, "Token is required");
		this.token = token;
		this.authority = NO_AUTHORITY; // thwart NPEs in the claims methods
	}

	/**
	 * @param token       - An OAuth2 Bearer Token
	 * @param authorities - A collection of {@see GrantedAuthority}s, one fo them being an {@see OAuth2AccessTokenAuthority}
	 */
	public OAuth2ResourceAuthenticationToken(String token, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);

		Assert.hasText(token, "Token is required");
		this.token = token;
		this.authority = (OAuth2AccessTokenAuthority) authorities.stream()
			.filter(authority -> authority instanceof OAuth2AccessTokenAuthority)
			.findFirst()
			.orElseThrow(() ->
				new IllegalArgumentException("authorities must contain one of type OAuth2AccessTokenAuthority"));

		setAuthenticated(true);
	}

	@Override
	public String getPrincipal() {
		return this.token;
	}

	@Override
	public String getCredentials() {
		return this.token;
	}

	/**
	 * Inspects its {@see OAuth2AccessTokenAuthority} for a claim by the given name and value
	 *
	 * @param name
	 * @param value
	 * @return
	 */
	public boolean hasClaim(String name, String value) {
		return this.authority.hasClaim(name, value);
	}

	/**
	 * Inspects its {@see OAuth2AccessTokenAuthority} for a claim by the given name whose value matches the given regex
	 *
	 * @param name
	 * @param regex
	 * @return
	 */
	public boolean hasClaimMatching(String name, String regex) {
		return this.authority.hasClaimMatching(name, regex);
	}

	/**
	 * A curried form of {@see hasClaim} and {@see hasClaimMatching}
	 *
	 * @param name
	 * @return
	 */
	public HasMatcher hasClaim(String name) {
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
