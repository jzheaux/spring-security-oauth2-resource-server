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

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * This is a bit cobbled together, but it gives an idea of the current state of integration.
 *
 * My thinking, so far, is that if the KeycloakAuthenticationToken is important to folks downstream, then
 * we can preserve that and simply adapt it when it comes to evaluating access expressions. That's what is
 * demonstrated in this sample.
 *
 * I think that, ideally, we'd be able to apply oauth2().resourceServer() and still play nicely with Keycloak's
 * Spring Security adapter which might be achieved by having Keycloak just use Spring Security's bearer token
 * filter and entry point instead of their own. Today, both libraries overlap at these two points.
 *
 * Or, if the KeycloakAuthenticationToken isn't important downstream, it might be as simple as creating
 * custom Keycloak token resolvers, like a custom JwtDecoder for JWT processing.
 *
 * @author Josh Cummings
 */
@SpringBootApplication
public class KeycloakAdapterApplication {

	public static void main(String[] args) {
		SpringApplication.run(KeycloakAdapterApplication.class, args);
	}
}
