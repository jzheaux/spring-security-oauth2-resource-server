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

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.AuthoritiesPopulator;
import org.springframework.security.oauth2.core.ScopeGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.resourceserver.authentication.JwtAccessTokenAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * An extract for getting authorities from a Keycloak-issued Bearer token
 *
 * @author Josh Cummings
 */
public class KeycloakAuthoritiesPopulator implements AuthoritiesPopulator {

	private GrantedAuthoritiesMapper authoritiesMapper = authorities -> authorities;

	@Override
	public Authentication populateAuthorities(Authentication authentication) {
		if ( authentication instanceof JwtAccessTokenAuthenticationToken ) {
			Jwt jwt = ((JwtAccessTokenAuthenticationToken) authentication).getJwt();

			Map<String, Object> attributes = jwt.getClaims();

			Collection<? extends GrantedAuthority> authorities =
					Optional.ofNullable(
									(Map<String, Object>) attributes.get("realm_access"))
							.map(realmAccess ->
									(List<String>) realmAccess.get("roles"))
							.orElse(Collections.emptyList())
							.stream()
							.map(ScopeGrantedAuthority::new)
							.collect(Collectors.toList());

			authorities = this.authoritiesMapper.mapAuthorities(authorities);

			return new JwtAccessTokenAuthenticationToken(jwt, authorities);
		} else {
			return authentication;
		}
	}

	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		Assert.notNull(authoritiesMapper, "authoritiesMapper cannot be null");
		this.authoritiesMapper = authoritiesMapper;
	}
}
