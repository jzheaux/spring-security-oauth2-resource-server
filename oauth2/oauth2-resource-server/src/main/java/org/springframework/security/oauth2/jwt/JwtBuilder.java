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
package org.springframework.security.oauth2.jwt;

import org.springframework.util.Assert;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public final class JwtBuilder {
	private final String token;

	private final Map<String, Object> headers;
	private final Map<String, Object> claims;

	public JwtBuilder(String token) {
		Assert.hasText(token, "token must have a value");

		this.token = token;
		this.headers = new HashMap<>();
		this.claims = new HashMap<>();
	}

	public JwtBuilder(String token, Map<String, Object> headers, Map<String, Object> claims) {
		Assert.hasText(token, "token must have a value");
		Assert.notEmpty(headers, "headers must not be empty");
		Assert.notEmpty(claims, "claims must not be empty");

		this.token = token;
		this.headers = new HashMap<>(headers);
		this.claims = new HashMap<>(claims);

		this.audience(claims.get(JwtClaimNames.AUD));
		this.expiresAt(claims.get(JwtClaimNames.EXP));
		this.issuedAt(claims.get(JwtClaimNames.IAT));
		this.notBefore(claims.get(JwtClaimNames.NBF));
	}

	public JwtBuilder id(String id) {
		this.claims.put(JwtClaimNames.JTI, id);
		return this;
	}

	public JwtBuilder audience(String audience) {
		return this.audience((Object) audience);
	}

	public JwtBuilder audience(Collection<String> audience) {
		return this.audience((Object) audience);
	}

	public JwtBuilder expiresAt(Long expiresAt) {
		return this.expiresAt((Object) expiresAt);
	}

	public JwtBuilder expiresAt(Date expiresAt) {
		return this.expiresAt((Object) expiresAt);
	}

	public JwtBuilder expiresAt(Instant expiresAt) {
		return this.expiresAt((Object) expiresAt);
	}

	public JwtBuilder issuer(String issuer) {
		this.claims.put(JwtClaimNames.ISS, issuer);
		return this;
	}

	public JwtBuilder issuedAt(Long issuedAt) {
		return this.issuedAt((Object) issuedAt);
	}

	public JwtBuilder issuedAt(Date issuedAt) {
		return this.issuedAt((Object) issuedAt);
	}

	public JwtBuilder issuedAt(Instant issuedAt) {
		return this.issuedAt((Object) issuedAt);
	}

	public JwtBuilder notBefore(Long notBefore) {
		return this.notBefore((Object) notBefore);
	}

	public JwtBuilder notBefore(Date notBefore) {
		return this.notBefore((Object) notBefore);
	}

	public JwtBuilder notBefore(Instant notBefore) {
		return this.notBefore((Object) notBefore);
	}

	public JwtBuilder subject(String subject) {
		this.claims.put(JwtClaimNames.SUB, subject);
		return this;
	}

	public JwtBuilder claim(String name, Object value) {
		this.claims.put(name, value);
		return this;
	}

	public JwtBuilder claims(Map<String, Object> claims) {
		this.claims.putAll(claims);
		return this;
	}

	public JwtBuilder header(String name, String value) {
		this.headers.put(name, value);
		return this;
	}

	public JwtBuilder headers(Map<String, Object> headers) {
		this.headers.putAll(headers);
		return this;
	}

	public Jwt build() {
		Instant exp = Instant.ofEpochSecond((Long) this.claims.get(JwtClaimNames.EXP));
		Instant iat = Instant.ofEpochSecond((Long) this.claims.get(JwtClaimNames.IAT));

		return new Jwt(this.token, iat, exp, this.headers, this.claims);
	}

	private JwtBuilder audience(Object audience) {
		this.claims.put(JwtClaimNames.AUD, coerce(audience, Collections.emptyList()));
		return this;
	}

	private JwtBuilder expiresAt(Object expiresAt) {
		this.claims.put(JwtClaimNames.EXP, coerce(expiresAt, Instant.MAX.getEpochSecond()));
		return this;
	}

	private JwtBuilder issuedAt(Object issuedAt) {
		this.claims.put(JwtClaimNames.IAT, coerce(issuedAt, Instant.MIN.getEpochSecond()));
		return this;
	}

	private JwtBuilder notBefore(Object notBefore) {
		this.claims.put(JwtClaimNames.NBF, coerce(notBefore, Instant.MIN.getEpochSecond()));
		return this;
	}

	private Collection<String> coerce(Object audience, Collection<String> def) {
		if ( audience instanceof String ) {
			return Arrays.asList((String) audience);
		}

		if ( audience instanceof Collection) {
			return (Collection<String>) audience;
		}

		return def;
	}

	private Long coerce(Object claim, Long def) {
		if ( claim instanceof Long ) {
			return (Long) claim;
		}

		if ( claim instanceof Date ) {
			return ((Date) claim).toInstant().getEpochSecond();
		}

		if ( claim instanceof Instant ) {
			return ((Instant) claim).getEpochSecond();
		}

		return def;
	}

}
