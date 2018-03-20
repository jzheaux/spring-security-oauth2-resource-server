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

import com.auth0.jwt.interfaces.RSAKeyProvider;

import java.security.interfaces.RSAPrivateKey;

/**
 * A {@link RSAKeyProvider} whose name makes it clear that it is only intended for
 * providing public keys.
 * <p>
 * Frankly, I'm unclear why auth0 conflates the two since one would suppose that it would be common
 * for reliant parties to always be verifying and never signing.
 */
public interface PublicKeyOnlyRSAKeyProvider extends RSAKeyProvider {
	@Override
	default RSAPrivateKey getPrivateKey() {
		throw new UnsupportedOperationException("how dare you!");
	}

	@Override
	default String getPrivateKeyId() {
		throw new UnsupportedOperationException("how dare you!");
	}
}
