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
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author Josh Cummings
 */
public class Auth0JwtAccessTokenConverter extends JwtAccessTokenConverter {
	private JWTVerifier verifier;

	public Auth0JwtAccessTokenConverter(JWTVerifier verifier) {
		this.verifier = verifier;
	}

	@Override
	protected Map<String, Object> decode(String token) {
		try {
			DecodedJWT decoded = verifier.verify(token);

			Map<String, Object> claims =
				decoded.getClaims().entrySet().stream()
					.collect(Collectors.toMap(Map.Entry::getKey,
						e -> e.getValue().as(Object.class)));

			putAsLongSeconds(claims, JwtClaimNames.IAT, decoded.getIssuedAt());
			putAsLongSeconds(claims, JwtClaimNames.EXP, decoded.getExpiresAt());
			putAsLongSeconds(claims, JwtClaimNames.NBF, decoded.getNotBefore());

			return claims;
		} catch (TokenExpiredException expired) {
			throw new InvalidTokenException(expired.getMessage());
		} catch (JWTVerificationException invalid) {
			throw new InvalidTokenException(invalid.getMessage());
		}
	}

	private void putAsLongSeconds(Map<String, Object> claims, String claim, Date date) {
		if ( date != null ) {
			claims.put(claim, date.getTime() / 1000); // convert to seconds
		}
	}
}
