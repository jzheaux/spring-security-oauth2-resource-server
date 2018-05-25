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

package cli;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.converters.ISO8601DateConverter;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jose.jws.JwsBuilder;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.util.StringUtils;
import support.Keys;

import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class Signer {
	public static class DateConverter implements IStringConverter<Instant> {
		IStringConverter<Date> converter = new ISO8601DateConverter("");

		@Override
		public Instant convert(String value) {
			if ( "min".equalsIgnoreCase(value) ) {
				return Instant.now().minus(1000*365, ChronoUnit.DAYS);
			}

			if ("max".equalsIgnoreCase(value)) {
				return Instant.now().plus(1000*365, ChronoUnit.DAYS);
			}

			if ("now".equalsIgnoreCase(value) ) {
				return Instant.now();
			}

			if ( value.chars().allMatch(Character::isDigit) ) {
				return Instant.ofEpochSecond(Long.parseLong(value));
			}

			return this.converter.convert(value).toInstant();
		}
	}

	public static class KeyConverter implements IStringConverter<Key> {
		@Override
		public Key convert(String value) {
			return Keys.pkcs8(new FileSystemResource(value));
		}
	}

	@Parameter(names = { "-iss", "--issuer"})
	String issuer;

	@Parameter(names = { "-sub", "--subject"})
	String subject;

	@Parameter(names = { "-aud", "--audience" })
	List<String> audience = new ArrayList<>();

	@Parameter(names = { "-iat", "--issuedat" }, converter = DateConverter.class)
	Instant issuedAt;

	@Parameter(names = { "-exp", "--expiresat" }, converter = DateConverter.class)
	Instant expiresAt;

	@Parameter(names = { "-nbf", "--notbefore" }, converter = DateConverter.class)
	Instant notBefore;

	@Parameter(names = { "-jti", "--id" })
	String id;

	@Parameter(names = { "-scp", "--scope" })
	List<String> scopes = new ArrayList<>();

	@Parameter(names = { "-with" }, converter = KeyConverter.class, required = true)
	Key sign;

	public String run() {
		JwsBuilder jws = JwsBuilder
				.withAlgorithm(JwsAlgorithms.RS256);

		if (StringUtils.hasText(issuer)) {
			jws.claim(JwtClaimNames.ISS, issuer);
		}

		if (StringUtils.hasText(subject)) {
			jws.claim(JwtClaimNames.SUB, subject);
		}

		if (!audience.isEmpty()) {
			jws.claim(JwtClaimNames.AUD, audience);
		}

		if (issuedAt != null) {
			jws.claim(JwtClaimNames.IAT, issuedAt.getEpochSecond());
		}

		if (expiresAt != null) {
			jws.claim(JwtClaimNames.EXP, expiresAt.getEpochSecond());
		}

		if ( this.notBefore != null ) {
			jws.claim(JwtClaimNames.NBF, this.notBefore.getEpochSecond());
		}

		if ( this.id == null ) {
			jws.claim(JwtClaimNames.JTI, UUID.randomUUID().toString());
		} else {
			jws.claim(JwtClaimNames.JTI, this.id);
		}

		for ( String scope : scopes ) {
			jws.scope(scope);
		}

		return jws.sign(this.sign).build();
	}

	public static void main(String[] args) {
		Signer signer = new Signer();
		JCommander.newBuilder()
				.addObject(signer)
				.build()
				.parse(args);

		System.out.println(signer.run());
	}
}
