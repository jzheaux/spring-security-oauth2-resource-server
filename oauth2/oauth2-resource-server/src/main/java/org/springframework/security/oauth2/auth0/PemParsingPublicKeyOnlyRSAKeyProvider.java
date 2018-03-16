package org.springframework.security.oauth2.auth0;

import org.springframework.security.crypto.codec.Base64;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

/**
 * A {@link PublicKeyOnlyRSAKeyProvider} that reads in an RSA public key and converts it from
 * PEM format (i.e. Base64-encoded) into DER format.
 * <p>
 * I realize that Bouncycastle is more feature-rich, but this sufficed for me and saved me a
 * dependency.
 */
public class PemParsingPublicKeyOnlyRSAKeyProvider implements PublicKeyOnlyRSAKeyProvider {
	private static final String PUBLIC_KEY_HEADER_FOOTER_SEGMENT = "PUBLIC KEY";

	private final RSAPublicKey key;

	public PemParsingPublicKeyOnlyRSAKeyProvider(InputStream is) {
		try (Scanner keyBytes = new Scanner(is)) {

			StringBuilder sb = new StringBuilder();
			while (keyBytes.hasNextLine()) {
				String line = keyBytes.nextLine();
				if (!line.contains(PUBLIC_KEY_HEADER_FOOTER_SEGMENT)) {
					sb.append(line);
				}
			}

			byte[] decoded = Base64.decode(sb.toString().getBytes());
			X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			key = (RSAPublicKey) kf.generatePublic(spec);
		} catch (Exception e) {
			throw new IllegalArgumentException(e);
		}
	}

	@Override
	public RSAPublicKey getPublicKeyById(String s) {
		return key;
	}
}
