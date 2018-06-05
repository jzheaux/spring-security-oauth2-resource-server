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
package sample;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.SignatureException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtBuilder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * @author Josh Cummings
 */
public class JJwtJwtDecoder implements JwtDecoder {
	private final JwtParser parser;

	public JJwtJwtDecoder(JwtParser parser) {
		this.parser = parser;
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		try {
			Jws<Claims> jws = this.parser.parseClaimsJws(token);

			return new JwtBuilder(token, jws.getHeader(), jws.getBody()).build();
		} catch (SignatureException expired) {
			throw new JwtException(expired.getMessage());
		}
	}
}
