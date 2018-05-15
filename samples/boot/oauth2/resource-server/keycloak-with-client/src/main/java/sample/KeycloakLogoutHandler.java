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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Propagates logouts to Keycloak.
 *
 * Necessary because Spring Security 5 (currently) doesn't support
 * end-session-endpoints.
 *
 * @author Thomas Darimont
 */
public class KeycloakLogoutHandler extends SecurityContextLogoutHandler {
	private final Logger log = LoggerFactory.getLogger(this.getClass());

	private final RestTemplate restTemplate;

	public KeycloakLogoutHandler(RestTemplate restTemplate) {
		this.restTemplate = restTemplate;
	}

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		super.logout(request, response, authentication);

		propagateLogoutToKeycloak((OidcUser) authentication.getPrincipal());
	}

	private void propagateLogoutToKeycloak(OidcUser user) {

		String endSessionEndpoint = user.getIssuer() + "/protocol/openid-connect/logout";

		UriComponentsBuilder builder = UriComponentsBuilder //
				.fromUriString(endSessionEndpoint) //
				.queryParam("id_token_hint", user.getIdToken().getTokenValue());

		ResponseEntity<String> logoutResponse = restTemplate.getForEntity(builder.toUriString(), String.class);
		if (logoutResponse.getStatusCode().is2xxSuccessful()) {
			log.info("Successfulley logged out in Keycloak");
		} else {
			log.info("Could not propagate logout to Keycloak");
		}
	}
}
