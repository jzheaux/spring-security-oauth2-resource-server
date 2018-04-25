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

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.JWTProcessor;

import java.util.LinkedHashMap;
import java.util.Map;

public class NimbusJwtDecoder implements JwtDecoder {
	private final JWTProcessor<SecurityContext> jwtProcessor;

	public NimbusJwtDecoder(JWTProcessor<SecurityContext> jwtProcessor) {
		this.jwtProcessor = jwtProcessor;
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
