package org.springframework.security.oauth2.core.bearer;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.resource.authentication.OAuth2ResourceAuthenticationToken;

import java.util.*;

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
		this.authority = "ROLE_USER"; //TODO what should go here?? I suppose that this is, indeed a user, but really, I wouldn't encourage folks to use it to make decisions
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
