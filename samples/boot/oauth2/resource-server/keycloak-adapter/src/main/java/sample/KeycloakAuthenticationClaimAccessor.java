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

package sample;

import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.springframework.security.oauth2.jwt.JwtClaimAccessor;
import org.springframework.util.Assert;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * @author Josh Cummings
 */
public class KeycloakAuthenticationClaimAccessor implements JwtClaimAccessor {
	private AccessToken token;

	public KeycloakAuthenticationClaimAccessor(KeycloakAuthenticationToken token) {
		Assert.notNull(token, "token must not be null");
		Assert.isInstanceOf(SimpleKeycloakAccount.class, token.getDetails(),
				"details must be of type SimpleKeycloakAccount");

		this.token = ((SimpleKeycloakAccount) token.getDetails()).getKeycloakSecurityContext().getToken();
	}

	@Override
	public URL getIssuer() {
		return Optional.ofNullable(this.token.getIssuer())
				.map(this::toURL)
				.orElse(null);
	}

	@Override
	public List<String> getAudience() {
		return Optional.ofNullable(this.token.getAudience())
				.map(audience -> Arrays.asList(audience))
				.orElse(Collections.emptyList());
	}

	@Override
	public Instant getNotBefore() {
		return Instant.ofEpochSecond(this.token.getNotBefore());
	}

	@Override
	public Instant getExpiresAt() {
		return Instant.ofEpochSecond(this.token.getExpiration());
	}

	@Override
	public Instant getIssuedAt() {
		return Instant.ofEpochSecond(this.token.getIssuedAt());
	}

	@Override
	public String getSubject() {
		return this.token.getSubject();
	}

	@Override
	public String getId() {
		return this.token.getId();
	}

	@Override
	public Map<String, Object> getClaims() {
		return this.token.getOtherClaims();
	}

	private URL toURL(String url) {
		try {
			return new URL(url);
		} catch (MalformedURLException e) {
			throw new IllegalStateException(e);
		}
	}
}
