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
package org.springframework.security.samples.config;

import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;

public class PemParsingPublicKeyOnlyRSAKeyProviderTests {
	@Test
	public void whenPemEncoded_thenCanParse() throws IOException {
		InputStream is = this.getClass()
			.getClassLoader().getResourceAsStream("id_rsa.pub");

		PemParsingPublicKeyOnlyRSAKeyProvider provider =
			new PemParsingPublicKeyOnlyRSAKeyProvider(is);

		RSAPublicKey key = provider.getPublicKeyById("123");

		assertThat(key.getPublicExponent()).isEqualTo(new BigInteger("65537"));
	}
}
