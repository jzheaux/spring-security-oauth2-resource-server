package org.springframework.security.samples.oauth2.rs.auth0;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class Auth0JwtDecoderJwkSupport implements JwtDecoder {
	private JWTVerifier verifier;

	public Auth0JwtDecoderJwkSupport(JWTVerifier verifier) {
		this.verifier = verifier;
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		try {
			DecodedJWT decoded = verifier.verify(token);

			Instant issuedAt = Instant.ofEpochMilli(decoded.getIssuedAt().getTime());
			Instant expiresAt = Instant.ofEpochMilli(decoded.getExpiresAt().getTime());

			Map<String, Object> claims =
				decoded.getClaims().entrySet().stream()
					.collect(Collectors.toMap(Map.Entry::getKey,
						e -> e.getValue().as(Object.class)));

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
}
