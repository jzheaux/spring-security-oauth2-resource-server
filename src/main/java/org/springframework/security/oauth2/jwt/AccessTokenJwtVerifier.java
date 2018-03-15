package org.springframework.security.oauth2.jwt;

import org.springframework.util.Assert;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * An implementation of {@see JwtVerifier} for verifying claims in a Jwt-based access token
 *
 * <p>
 * Because clocks can differ between the Jwt source, say the Authorization Server, and its destination, say the
 * Resource Server, there is a default clock leeway exercised when deciding if the current time is within the Jwt's
 * specified operating window
 *
 * <p>
 * Custom verification can be appended to instances of this class by providing a custom implementation of
 * {@see JwtVerifier}
 *
 * @author Josh Cummings
 * @since 5.1
 * @see Jwt
 * @see JwtVerifier
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token (JWT)</a>
 */
public class AccessTokenJwtVerifier implements JwtVerifier {
	private static final Duration DEFAULT_MAX_CLOCK_SKEW = Duration.of(60, ChronoUnit.SECONDS);

	private final JwtVerifier additionalVerification;

	private final Duration maxClockSkew;

	/**
	 * A basic instance with no custom verification and the default max clock skew
	 */
	public AccessTokenJwtVerifier() {
		this((jwt) -> {});
	}

	public AccessTokenJwtVerifier(JwtVerifier jwtVerifier) {
		this(jwtVerifier, DEFAULT_MAX_CLOCK_SKEW);
	}

	public AccessTokenJwtVerifier(JwtVerifier jwtVerifier, Duration maxClockSkew) {
		Assert.notNull(jwtVerifier, "jwtVerifier cannot be null");
		Assert.notNull(maxClockSkew, "maxClockSkew cannot be null");

		this.additionalVerification = jwtVerifier;
		this.maxClockSkew = maxClockSkew;
	}

	@Override
	public void verifyClaims(Jwt jwt) throws JwtException {
		Instant expiry = jwt.getExpiresAt();

		if ( expiry != null ) {
			if ( Instant.now().isAfter(expiry.plus(maxClockSkew)) ) {
				throw new JwtVerificationException(JwtError.EXPIRED, jwt);
			}
		}

		Instant notBefore = jwt.getNotBefore();

		if ( notBefore != null ) {
			if ( Instant.now().isBefore(expiry.minus(maxClockSkew)) ) {
				throw new JwtVerificationException(JwtError.NOT_BEFORE, jwt);
			}
		}

		additionalVerification.verifyClaims(jwt);
	}
}
