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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class NimbusJwtDecoder implements JwtDecoder {
	private final JWSAlgorithm jwsAlgorithm;
	private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

	public NimbusJwtDecoder(PublicKey publicKey) {
		this(JwsAlgorithms.RS256, publicKey);
	}

	public NimbusJwtDecoder(String jwsAlgorithm, PublicKey publicKey) {
		this.jwsAlgorithm = JWSAlgorithm.parse(jwsAlgorithm);

		JWSKeySelector<SecurityContext> jwsKeySelector =
				(jwsHeader, context) -> {
					if ( jwsHeader.getAlgorithm() == this.jwsAlgorithm ) {
						return Arrays.asList(publicKey);
					} else {
						return Collections.emptyList();
					}
				};

		this.jwtProcessor = new DefaultJWTProcessor<>();
		this.jwtProcessor.setJWSKeySelector(jwsKeySelector);
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		Jwt jwt;

		try {
			JWT parsedJwt = JWTParser.parse(token);

			// Verify the signature
			JWTClaimsSet jwtClaimsSet = this.jwtProcessor.process(parsedJwt, null);

			Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());

			jwt = new JwtBuilder(token, headers, jwtClaimsSet.getClaims()).build();
		} catch (Exception ex) {
			throw new JwtException("An error occurred while attempting to decode the Jwt: " + ex.getMessage(), ex);
		}

		return jwt;
	}
}
