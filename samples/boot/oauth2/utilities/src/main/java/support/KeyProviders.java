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
import org.springframework.security.oauth2.jwt.KeyProvider;
import org.springframework.security.oauth2.jwt.SingleKeyProvider;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;

/**
 * Targeted support for creating {@link KeyProvider}s from PEM-encoded RSA keys,
 * specifically from the filesystem, though these will work with any {@link InputStream}
 * or {@link Resource}.
 *
 * @author Josh Cummings
 */
public final class KeyProviders {
	public static KeyProvider x509(InputStream bits) {
		try {
			Key key = Keys.x509(bits);
			return (SingleKeyProvider) () -> key;
		} catch ( Exception e ) {
			throw new IllegalArgumentException(e);
		}
	}

	public static KeyProvider x509(Resource bits) {
		try {
			return x509(bits.getInputStream());
		} catch ( IOException e ) {
			throw new IllegalArgumentException(e);
		}
	}

	public static KeyProvider pkcs8(InputStream bits) {
		try {
			Key key = Keys.pkcs8(bits);
			return (SingleKeyProvider) () -> key;
		} catch ( Exception e ) {
			throw new IllegalArgumentException(e);
		}
	}

	public static KeyProvider pkcs8(Resource bits) {
		try {
			return pkcs8(bits.getInputStream());
		} catch ( IOException e ) {
			throw new IllegalArgumentException(e);
		}
	}
}
