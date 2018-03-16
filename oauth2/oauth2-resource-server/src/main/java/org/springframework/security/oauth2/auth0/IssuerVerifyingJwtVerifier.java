package org.springframework.security.oauth2.auth0;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.springframework.util.Assert;

/**
 * A class for representing an issuer-based {@link JWTVerifier} instance.
 * <p>
 * This class essentially delegates to {@link JWTVerifier} in an effort to provide
 * an extension point, though if I were taking a more modular approach, I would probably
 * create a DelegatingJwtVerifier which this and other classes could then extend from;
 * I've left that extra work out in favor of conciseness in the context of the coding exercise.
 */
public class IssuerVerifyingJwtVerifier implements JwtVerifier {
	private final JWTVerifier verifier;

	public IssuerVerifyingJwtVerifier(String issuer, RSAKeyProvider provider) {
		Assert.hasText(issuer, "issuer is required");
		Assert.notNull(provider, "provider is required");

		Algorithm alg = Algorithm.RSA256(provider);
		verifier = JWT.require(alg).withIssuer(issuer).build();
	}

	@Override
	public DecodedJWT verify(String token) {
		return verifier.verify(token);
	}
}
