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

package support;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jose.jws.JwsBuilder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderLocalKeySupport;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

public class JwsBuilderTests {
	KeyPairGenerator generator;

	KeyPair rsa;

	@Before
	public void createKeyFactory() throws Exception {
		this.generator = KeyPairGenerator.getInstance("RSA");
		this.rsa = generator.generateKeyPair();
	}

	@Test
	public void serializeWhenScopeExcludedThenScopeIsntInResultingJwt() {

		String encoded = JwsBuilder.withAlgorithm(JwsAlgorithms.RS256)
				.expiresAt(Instant.now().plusSeconds(3600))
				.sign(this.rsa.getPrivate())
				.build();

		Jwt decoded =
				new NimbusJwtDecoderLocalKeySupport(header -> Arrays.asList(this.rsa.getPublic()))
						.decode(encoded);

		assertThat(decoded.getClaims().get("scope")).isNull();
	}

	@Test
	public void serializeWhenSignedWithoutKidThenKidInstInResultingJwt() {
		String encoded = JwsBuilder.withAlgorithm(JwsAlgorithms.RS256)
				.id()
				.sign(this.rsa.getPrivate())
				.build();

		Jwt decoded =
				new NimbusJwtDecoderLocalKeySupport(header -> Arrays.asList(this.rsa.getPublic()))
						.decode(encoded);

		assertThat(decoded.getHeaders().get("kid")).isNull();
	}
}
