package org.springframework.security.samples.oauth2.rs.auth0;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import java.security.interfaces.RSAPublicKey;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class PublicKeyOnlyRSAKeyProviderTests {
	PublicKeyOnlyRSAKeyProvider provider = (s) -> null;

	@Test
	public void whenTryPrivateKey_thenError() {
		assertThatThrownBy(() -> this.provider.getPrivateKey())
			.isInstanceOf(UnsupportedOperationException.class);
	}

	@Test
	public void whenTryPrivateKeyId_thenError() {
		assertThatThrownBy(() -> this.provider.getPrivateKeyId())
			.isInstanceOf(UnsupportedOperationException.class);
	}
}
