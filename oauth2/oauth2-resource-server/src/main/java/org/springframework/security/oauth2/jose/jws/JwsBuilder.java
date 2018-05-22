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
package org.springframework.security.oauth2.jose.jws;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import net.minidev.json.JSONObject;
import org.springframework.security.oauth2.jose.jwk.JwkSetBuilder;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A convenience class for working with Nimbus's {@link JWSObject} API
 *
 * @author Josh Cummings
 */
public class JwsBuilder {
	private JWSHeader.Builder header;
	private JSONObject payload = new JSONObject();
	private Set<String> scope = new LinkedHashSet<>();

	private JWSObject jws;

	private JwsBuilder(String algorithm) {
		JWSAlgorithm alg = JWSAlgorithm.parse(algorithm);
		this.header = new JWSHeader.Builder(alg);
	}

	/**
	 * Instantiate a JwsBuilder with the given {@code algorithm}
	 *
	 * @param algorithm
	 * @return
	 */
	public static JwsBuilder withAlgorithm(String algorithm) {
		return new JwsBuilder(algorithm);
	}

	/**
	 * Add or update a field to the payload of the JWT
	 *
	 * @param name
	 * @param value
	 * @return
	 */
	public JwsBuilder claim(String name, Object value) {
		this.payload.appendField(name, value);
		return this;
	}

	/**
	 * Set the 'exp' field on the JWT
	 *
	 * @param expiresAt
	 * @return
	 */
	public JwsBuilder expiresAt(Instant expiresAt) {
		this.payload.appendField(JwtClaimNames.EXP, expiresAt.getEpochSecond());
		return this;
	}

	/**
	 * Append to the 'scope' field on the JWT
	 *
	 * @param scope
	 * @return
	 */
	public JwsBuilder scope(String scope) {
		this.scope.add(scope);
		return this;
	}

	/**
	 * Sign the JWT with any valid JWK in the provided JWK set
	 *
	 * Note that this method is deterministic. Given the same JWK set, it will always
	 * pick the same JWK across multiple invocations in the same runtime.
	 *
	 * Also note that this method should only be used when the test genuinely does not
	 * care which JWK is chosen.
	 *
	 * @param provider - the key provider to use
	 *
	 * @return
	 */
	public JwsBuilder signWithAny(JwkSetBuilder provider) {
		Map<String, Key> keys = provider.getKeyMap();

		if ( keys.isEmpty() ) {
			throw new IllegalStateException("no keys configured in provided JwkSetBuilder");
		} else {
			Map.Entry<String, Key> entry = keys.entrySet().iterator().next();
			return sign(entry.getKey(), entry.getValue());
		}
	}



	/**
	 * Sign the JWT with the given kid and JWK set
	 *
	 * @param keyId
	 * @param builder - A JWK set containing an JWK with key {@code keyId}
	 * @return
	 */
	public JwsBuilder sign(String keyId, JwkSetBuilder builder) {
		return sign(keyId, builder.getKeyById(keyId));
	}

	/**
	 * Sign the JWT with the given kid and key
	 *
	 * @param keyId
	 * @return
	 */
	public JwsBuilder sign(String keyId, Key key) {
		this.header.keyID(keyId);
		return this.sign(key);
	}

	/**
	 * Sign the JWT with the given key
	 *
	 * @return
	 */
	public JwsBuilder sign(Key key) {
		this.claim("scope", this.scope.stream().collect(Collectors.joining(" ")));

		this.jws =
				new JWSObject(
						this.header.build(),
						new Payload(this.payload)
				);

		try {
			if ( key instanceof RSAPrivateKey ) {
				this.jws.sign(new RSASSASigner((RSAPrivateKey) key));
			} else if ( key instanceof ECPrivateKey ) {
				this.jws.sign(new ECDSASigner((ECPrivateKey) key));
			} else if ( key instanceof SecretKey ) {
				this.jws.sign(new MACSigner((SecretKey) key));
			}
		} catch ( JOSEException jex ) {
			throw new IllegalArgumentException(jex);
		}

		return this;

	}

	/**
	 * Build the JWT
	 *
	 * @return
	 */
	public String build() {
		if ( this.jws == null ) {
			throw new IllegalStateException("attempted to serialize an unsigned JWT");
		}

		return this.jws.serialize();
	}
}
