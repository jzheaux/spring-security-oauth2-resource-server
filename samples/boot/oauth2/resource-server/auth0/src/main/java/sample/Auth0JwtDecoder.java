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

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author Josh Cummings
 */
public class Auth0JwtDecoder implements JwtDecoder {
	private JWTVerifier verifier;

	public Auth0JwtDecoder(JWTVerifier verifier) {
		this.verifier = verifier;
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		try {
			DecodedJWT decoded = verifier.verify(token);

			Instant issuedAt = toInstant(decoded.getIssuedAt(), Instant.MIN);
			Instant expiresAt = toInstant(decoded.getExpiresAt(), Instant.MAX);
			Instant notBefore = toInstant(decoded.getNotBefore(), Instant.MIN);

			Map<String, Object> claims =
				decoded.getClaims().entrySet().stream()
					.collect(Collectors.toMap(Map.Entry::getKey,
						e -> e.getValue().as(Object.class)));

			claims.put(JwtClaimNames.IAT, issuedAt);
			claims.put(JwtClaimNames.EXP, expiresAt);
			claims.put(JwtClaimNames.NBF, notBefore);

			Map<String, Object> headerClaims = new HashMap<>();
			headerClaims.put(PublicClaims.KEY_ID, decoded.getKeyId());
			headerClaims.put(PublicClaims.ALGORITHM, decoded.getAlgorithm());
			headerClaims.put(PublicClaims.CONTENT_TYPE, decoded.getContentType());
			headerClaims.put(PublicClaims.TYPE, decoded.getType());

			return new Jwt(token, issuedAt, expiresAt, headerClaims, claims);
		} catch (TokenExpiredException expired) {
			throw new JwtException(expired.getMessage());
		} catch (JWTVerificationException invalid) {
			throw new JwtException(invalid.getMessage());
		}
	}

	private Instant toInstant(Date date, Instant defaultInstant) {
		if ( date == null ) {
			return defaultInstant;
		}

		return Instant.ofEpochMilli(date.getTime());
	}
}
