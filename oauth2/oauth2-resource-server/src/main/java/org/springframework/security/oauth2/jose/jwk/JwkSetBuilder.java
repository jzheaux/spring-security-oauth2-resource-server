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
package org.springframework.security.oauth2.jose.jwk;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.SecretJWK;
import net.minidev.json.JSONObject;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * A convenience class for working with Nimbus's {@link JWK} API.
 *
 * @author Josh Cummings
 */
public class JwkSetBuilder {
	private final List<JWK> jwks;

	private JwkSetBuilder() {
		this.jwks = new ArrayList<>();
	}

	/**
	 * Generate an empty JWK set
	 */
	public static JwkSetBuilder empty() {
		return new JwkSetBuilder();
	}

	/**
	 * Generate an EC JWK, adding it to the list of available JWKs
	 *
	 * @return
	 */
	public JwkSetBuilder withEc() {
		this.jwks.add(ec().build());
		return this;
	}

	/**
	 * Generate an EC JWK, adding it to the list of available JWKs
	 *
	 * @param keyId
	 * @return
	 */
	public JwkSetBuilder withEc(String keyId) {
		this.jwks.add(ec().keyID(keyId).build());
		return this;
	}

	private ECKey.Builder ec() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(521); // yes, 521
			KeyPair keyPair = generator.generateKeyPair();

			return new ECKey.Builder(Curve.P_521, ((ECPublicKey) keyPair.getPublic()))
					.privateKey(keyPair.getPrivate())
					.keyUse(KeyUse.SIGNATURE);

		} catch ( NoSuchAlgorithmException ecMissing ) {
			throw new IllegalStateException(ecMissing);
		}
	}

	/**
	 * Generate an RSA JWK, adding it to the list of available JWKs.
	 *
	 * @return
	 */
	public JwkSetBuilder withRsa() {
		this.jwks.add(rsa().build());
		return this;
	}

	/**
	 * Generate an RSA JWK, adding it to the list of available JWKs.
	 *
	 * @param keyId
	 * @return
	 */
	public JwkSetBuilder withRsa(String keyId) {
		this.jwks.add(rsa().keyID(keyId).build());
		return this;
	}

	private RSAKey.Builder rsa() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			KeyPair kp = generator.generateKeyPair();

			return new RSAKey.Builder((RSAPublicKey) kp.getPublic())
					.privateKey(kp.getPrivate())
					.keyUse(KeyUse.SIGNATURE);
		} catch ( NoSuchAlgorithmException rsaMissing ) {
			throw new IllegalStateException(rsaMissing);
		}
	}

	/**
	 * Look up JWK by {@code keyId}
	 *
	 * @param keyId
	 * @return
	 */
	public Key getKeyById(String keyId) {
		return this.jwks.stream()
				.filter(jwk -> keyId.equals(jwk.getKeyID()))
				.findFirst()
				.map(this::extractKey)
				.orElse(null);
	}

	/**
	 * Extract kid and key from the JWKs already configured
	 *
	 * @return
	 */
	public Map<String, Key> getKeyMap() {
		return this.jwks.stream()
				.collect(
						Collectors.toMap(
								JWK::getKeyID,
								this::extractKey));
	}

	/**
	 * Convert the list into a JWK json set, the format being compatible
	 * with the expected response of a JWK set url.
	 *
	 * @return
	 */
	public String build() {
		return new JSONObject()
				.appendField("keys", this.jwks).toJSONString();
	}

	private Key extractKey(JWK jwk) {
		try {
			if ( jwk instanceof AsymmetricJWK ) {
				return ((AsymmetricJWK) jwk).toPrivateKey();
			} else if ( jwk instanceof SecretJWK ){
				return ((SecretJWK) jwk).toSecretKey();
			} else {
				return null;
			}
		} catch ( JOSEException failed ) {
			throw new IllegalArgumentException(failed);
		}
	}
}
