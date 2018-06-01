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
import java.util.LinkedHashMap;

/**
 * A {@link JwtDecoder} for Nimbus for locally-configured verification keys.
 *
 * @since 5.1
 * @author Josh Cummings
 */
public class NimbusJwtDecoderLocalKeySupport implements JwtDecoder {
	private final NimbusJwtDecoder decoder;

	public NimbusJwtDecoderLocalKeySupport(Key key) {
		this(key, JwsAlgorithms.RS256);
	}

	public NimbusJwtDecoderLocalKeySupport(Key key, String jwsAlgorithm) {
		this((header) -> Arrays.asList(key), jwsAlgorithm);
	}

	public NimbusJwtDecoderLocalKeySupport(KeyProvider provider) {
		this(provider, JwsAlgorithms.RS256);
	}

	public NimbusJwtDecoderLocalKeySupport(KeyProvider provider, String jwsAlgorithm) {
		Assert.notNull(provider, "provider cannot be null");
		Assert.hasText(jwsAlgorithm, "jwsAlgorithm cannot be empty");

		this.decoder = delegate((jwsHeader, context) ->
				provider.provide(new LinkedHashMap<String, Object>(jwsHeader.toJSONObject())));
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		return this.decoder.decode(token);
	}

	private NimbusJwtDecoder delegate(JWSKeySelector<SecurityContext> jwsKeySelector) {
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
		jwtProcessor.setJWSKeySelector(jwsKeySelector);

		// Spring Security validates this claim independent of Nimbus
		jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {});

		return new NimbusJwtDecoder(jwtProcessor);
	}
}
