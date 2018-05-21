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

import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static support.Pem.PKCS8_PEM_HEADER_SEGMENT;
import static support.Pem.X509_PEM_HEADER_SEGMENT;

/**
 * Targeted support for reading pem-encoded RSA keys, specifically for the filesystem,
 * though will work with any input stream.
 *
 * @author Josh Cummings
 */
public final class Keys {
	private static final KeyFactory kf;

	static {
		try {
			kf = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	public static PublicKey x509(InputStream bits) {
		try {
			byte[] decoded = Pem.decode(X509_PEM_HEADER_SEGMENT, bits);
			EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
			return kf.generatePublic(spec);
		} catch ( Exception e ) {
			throw new IllegalArgumentException(e);
		}
	}

	public static PublicKey x509(Resource bits) {
		try {
			return x509(bits.getInputStream());
		} catch ( IOException e ) {
			throw new IllegalArgumentException(e);
		}
	}

	public static PrivateKey pkcs8(InputStream bits) {
		try {
			byte[] decoded = Pem.decode(PKCS8_PEM_HEADER_SEGMENT, bits);
			EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
			return kf.generatePrivate(spec);
		} catch ( Exception e ) {
			throw new IllegalArgumentException(e);
		}
	}

	public static PrivateKey pkcs8(Resource bits) {
		try {
			return pkcs8(bits.getInputStream());
		} catch ( IOException e ) {
			throw new IllegalArgumentException(e);
		}
	}
}
