package org.springframework.security.oauth2.auth0;

import com.auth0.jwt.interfaces.RSAKeyProvider;

import java.security.interfaces.RSAPrivateKey;

/**
 * A {@link RSAKeyProvider} whose name makes it clear that it is only intended for
 * providing public keys.
 * <p>
 * Frankly, I'm unclear why auth0 conflates the two since one would suppose that it would be common
 * for reliant parties to always be verifying and never signing.
 */
public interface PublicKeyOnlyRSAKeyProvider extends RSAKeyProvider {
	@Override
	default RSAPrivateKey getPrivateKey() {
		throw new UnsupportedOperationException("how dare you!");
	}

	@Override
	default String getPrivateKeyId() {
		throw new UnsupportedOperationException("how dare you!");
	}
}
