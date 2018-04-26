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
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;

/**
 * Base class for {@link AbstractAuthenticationToken} implementations
 * that expose common attributes between different OAuth 2.0 Access Token Formats.
 *
 * <p>
 * For example, a {@link Jwt} could expose it's {@link Jwt#getClaims() claims} via
 * {@link #getTokenAttributes()} or an &quot;Introspected&quot; OAuth 2.0 Access Token
 * could expose the attributes of the Introspection Response via {@link #getTokenAttributes()}.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2AccessToken
 * @see Jwt
 * @see <a target="_blank" href="https://tools.ietf.org/search/rfc7662#section-2.2">2.2 Introspection Response</a>
 */
public abstract class AbstractOAuth2AccessTokenAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private static final String DEFAULT_SCOPE_ATTRIBUTE_NAME = "scope";
	private String scopeAttributeName = DEFAULT_SCOPE_ATTRIBUTE_NAME;

	/**
	 * Sub-class constructor.
	 */
	protected AbstractOAuth2AccessTokenAuthenticationToken() {
		this(null);
	}

	/**
	 * Sub-class constructor.
	 *
	 * @param authorities the authorities assigned to the Access Token
	 */
	protected AbstractOAuth2AccessTokenAuthenticationToken(Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
	}

	/**
	 * Returns the attributes of the access token.
	 *
	 * @return a {@code Map} of the attributes in the access token.
	 */
	public abstract Map<String, Object> getTokenAttributes();

	/**
	 * Returns the attribute name used to access the scope(s) associated to the access token.
	 *
	 * @return the attribute name used to access the scope(s) associated to the access token
	 */
	public final String getScopeAttributeName() {
		return this.scopeAttributeName;
	}

	/**
	 * Sets the attribute name used to access the scope(s) associated to the access token.
	 *
	 * @param scopeAttributeName the attribute name used to access the scope(s) associated to the access token
	 */
	public final void setScopeAttributeName(String scopeAttributeName) {
		Assert.hasText(scopeAttributeName, "scopeAttributeName cannot be empty");
		this.scopeAttributeName = scopeAttributeName;
	}

	/**
	 * Returns {@code true} if {@code scope} is associated to the access token,
	 * otherwise returns {@code false}.
	 *
	 * @param scope the scope to check
	 *
	 * @return {@code true} if {@code scope} is associated to the access token, false otherwise
	 */
	public final boolean hasScope(String scope) {
		Assert.hasText(scope, "scope cannot be empty");
		if (CollectionUtils.isEmpty(this.getTokenAttributes())) {
			return false;
		}
		return Optional.ofNullable(this.getTokenAttributes().get(this.getScopeAttributeName()))
				.map(Object::toString)
				.filter(v -> v.contains(scope))
				.isPresent();
	}

	/**
	 * Returns {@code true} if {@code name} is available in {@link #getTokenAttributes()}
	 * and is equal to {@code value}, otherwise returns {@code false}.
	 *
	 * @param name the name of the token attribute to check
	 * @param value the value of the token attribute to compare
	 *
	 * @return {@code true} if {@code name} is available and is equal to {@code value}, false otherwise
	 */
	public final boolean hasAttribute(String name, String value) {
		Assert.hasText(name, "name cannot be empty");
		if (CollectionUtils.isEmpty(this.getTokenAttributes())) {
			return false;
		}
		return Optional.ofNullable(this.getTokenAttributes().get(name))
				.filter(v -> v.equals(value))
				.isPresent();
	}

	/**
	 * Returns {@code true} if {@code name} is available in {@link #getTokenAttributes()}
	 * and matches {@code regex}, otherwise returns {@code false}.
	 *
	 * @param name the name of the token attribute to check
	 * @param regex the regular expression used to match against the token attribute value
	 *
	 * @return {@code true} if {@code name} is available and matches {@code regex}, false otherwise
	 */
	public final boolean hasAttributeMatches(String name, String regex) {
		Assert.hasText(name, "name cannot be empty");
		Assert.hasText(regex, "regex cannot be empty");
		if (CollectionUtils.isEmpty(this.getTokenAttributes())) {
			return false;
		}
		return Optional.ofNullable(this.getTokenAttributes().get(name))
				.map(Object::toString)
				.filter(v -> v.matches(regex))
				.isPresent();
	}

	@Override
	public Object getPrincipal() {
		return "";
	}

	@Override
	public Object getCredentials() {
		return "";
	}
}
