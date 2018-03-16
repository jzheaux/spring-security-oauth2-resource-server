package org.springframework.security.samples.oauth2.rs.auth0;

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
