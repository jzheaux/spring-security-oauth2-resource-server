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

package sample;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.ClaimAccessorAuthoritiesExtractor;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @author Josh Cummings
 */
public class KeycloakClaimAccessorAuthoritiesExtractor implements ClaimAccessorAuthoritiesExtractor {

	private GrantedAuthoritiesMapper authoritiesMapper = authorities -> authorities;

	@Override
	public Collection<? extends GrantedAuthority> extractAuthorities(ClaimAccessor accessor) {
		Collection<? extends GrantedAuthority> authorities =
				Optional.ofNullable(
								(Map<String, Object>) accessor.getClaims().get("realm_access"))
						.map(realmAccess ->
								(List<String>) realmAccess.get("roles"))
						.orElse(Collections.emptyList())
						.stream()
						.map(SimpleGrantedAuthority::new)
						.collect(Collectors.toList());

		return this.authoritiesMapper.mapAuthorities(authorities);
	}

	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		Assert.notNull(authoritiesMapper, "authoritiesMapper cannot be null");
		this.authoritiesMapper = authoritiesMapper;
	}
}
