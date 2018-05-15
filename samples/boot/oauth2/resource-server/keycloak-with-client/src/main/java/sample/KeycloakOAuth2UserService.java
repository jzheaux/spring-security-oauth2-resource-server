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
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @author Thomas Darimont
 * @author Josh Cummings
 */
public class KeycloakOAuth2UserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

	private final GrantedAuthoritiesMapper authoritiesMapper;

	private final OidcUserService delegate = new OidcUserService();

	public KeycloakOAuth2UserService(GrantedAuthoritiesMapper authoritiesMapper) {
		this.authoritiesMapper = authoritiesMapper;
	}

	/**
	 * Augments {@link OidcUserService#loadUser(OidcUserRequest)} to add authorities
	 * provided by Keycloak.
	 *
	 * Needed because {@link OidcUserService#loadUser(OidcUserRequest)} (currently)
	 * does not provide a hook for adding custom authorities from a
	 * {@link OidcUserRequest}.
	 */
	@Override
	public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {

		OidcUser user = delegate.loadUser(userRequest);

		String clientId = userRequest.getClientRegistration().getClientId();

		ClaimAccessor claims = () -> user.getClaims();

		Collection<? extends GrantedAuthority> authorities =
				extract(claims, clientId).stream()
						.map(SimpleGrantedAuthority::new)
						.collect(Collectors.toList());

		if ( authorities != null ) {
			authorities = authoritiesMapper.mapAuthorities(authorities);
		}

		return new DefaultOidcUser(new LinkedHashSet<>(authorities), userRequest.getIdToken(), user.getUserInfo(), "preferred_username");
	}

	/**
	 * Extracts {@link String roles} from the AccessToken in
	 * the {@link OidcUserRequest}.
	 *
	 * @param claims
	 * @param clientId
	 * @return
	 */
	private List<String> extract(ClaimAccessor claims, String clientId) {
		Map<String, Object> attributes = claims.getClaims();

		return
				Optional.ofNullable(
								(Map<String, Object>) attributes.get("resource_access"))
						.map(resourceAccess ->
								(Map<String, Map<String, Object>>) resourceAccess.get(clientId))
						.map(clientResource ->
								(List<String>) clientResource.get("roles"))
						.orElse(Collections.emptyList());
	}
}
