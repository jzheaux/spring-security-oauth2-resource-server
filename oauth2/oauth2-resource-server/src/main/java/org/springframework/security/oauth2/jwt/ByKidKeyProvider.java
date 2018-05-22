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

package org.springframework.security.oauth2.jwt;

import java.security.Key;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A class for looking up verification keys by the kid field in
 * a JWTs header.
 *
 * @since 5.1
 * @author Josh Cummings
 */
public class ByKidKeyProvider<T extends Key> implements KeyProvider<T> {
	private final Map<String, T> keys;

	public ByKidKeyProvider(String kid, T key) {
		this.keys = new HashMap<>();
		this.keys.put(kid, key);
	}

	public ByKidKeyProvider(Map<String, T> keys) {
		this.keys = keys;
	}

	@Override
	public List<T> provide(Map<String, Object> header) {
		return Optional.ofNullable(this.keys.get(header.get("kid")))
				.map(Arrays::asList)
				.orElse(Collections.emptyList());
	}
}
