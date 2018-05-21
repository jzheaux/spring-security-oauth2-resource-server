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

import org.junit.Test;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import support.Keys;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Josh Cummings
 */
public class JwtRoundtripTests {
	ByteArrayOutputStream sign = new ByteArrayOutputStream();
	ByteArrayOutputStream verify = new ByteArrayOutputStream();

	@Test
	public void verifyWhenUsingGeneratedKeysAndSignedJwtThenSignaturePasses()
		throws Exception {

		KeyGen keygen = new KeyGen();
		keygen.privateOutput = this.sign;
		keygen.publicOutput = this.verify;
		keygen.run();

		assertThat(this.sign.size()).isGreaterThan(0);
		assertThat(this.verify.size()).isGreaterThan(0);

		Signer signer = new Signer();
		signer.sign = Keys.pkcs8(new ByteArrayInputStream(this.sign.toByteArray()));
		signer.issuer = "https://example.com";
		String jwt = signer.run();

		Verifier verifier = new Verifier();
		verifier.verify = Keys.x509(new ByteArrayInputStream(this.verify.toByteArray()));
		verifier.jwt = jwt;

		assertThat(verifier.run()).containsEntry(JwtClaimNames.ISS, signer.issuer);
	}
}
