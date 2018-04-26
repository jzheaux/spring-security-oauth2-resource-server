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

import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.util.Assert;

import java.security.Key;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * A {@link JwtDecoder} for Nimbus for locally-configured verification keys.
 *
 * @since 5.1
 * @author Josh Cummings
 */
public class NimbusJwtDecoderLocalKeySupport implements JwtDecoder {
	private final NimbusJwtDecoder decoder;

	public NimbusJwtDecoderLocalKeySupport(String keyId, Key key) {
		this(keyId, key, JwsAlgorithms.RS256);
	}

	public NimbusJwtDecoderLocalKeySupport(String keyId, Key key, String jwsAlgorithm) {
		Assert.notNull(key, "key cannot be null");
		Assert.hasText(jwsAlgorithm, "jwsAlgorithm cannot be empty");

		Map<String, Key> keys = new HashMap<>();
		keys.put(keyId, key);

		this.decoder = delegate(selector(keys, jwsAlgorithm));
	}

	public NimbusJwtDecoderLocalKeySupport(Map<String, Key> keys) {
		this(keys, JwsAlgorithms.RS256);
	}

	public NimbusJwtDecoderLocalKeySupport(Map<String, Key> keys, String jwsAlgorithm) {
		Assert.notEmpty(keys, "keys cannot be empty");
		Assert.hasText(jwsAlgorithm, "jwsAlgorithm cannot be empty");

		this.decoder = delegate(selector(keys, jwsAlgorithm));
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		return this.decoder.decode(token);
	}

	private JWSKeySelector<SecurityContext> selector(Map<String, Key> keys, String jwsAlgorithm) {
		return (jwsHeader, context) ->
				jwsHeader.getAlgorithm().toString().equals(jwsAlgorithm) &&
						keys.containsKey(jwsHeader.getKeyID()) ?
							Arrays.asList(keys.get(jwsHeader.getKeyID())) :
							Collections.emptyList();
	}

	private NimbusJwtDecoder delegate(JWSKeySelector<SecurityContext> jwsKeySelector) {
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
		jwtProcessor.setJWSKeySelector(jwsKeySelector);

		return new NimbusJwtDecoder(jwtProcessor);
	}
}
