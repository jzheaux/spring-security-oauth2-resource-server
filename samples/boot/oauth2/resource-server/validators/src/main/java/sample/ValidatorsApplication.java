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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver.ResourceServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.KeyProvider;
import org.springframework.security.oauth2.resourceserver.authentication.JwtAccessTokenAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.PublicKey;

import static org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver.ValidatorConfigurer.audience;
import static org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver.ValidatorConfigurer.claim;
import static org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver.ValidatorConfigurer.issuer;
import static org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver.ValidatorConfigurer.timestamps;

/**
 * @author Josh Cummings
 */
@SpringBootApplication
public class ValidatorsApplication {
	@RestController
	public class SimpleController {

		@GetMapping("/ok")
		@PreAuthorize("@oauth2.hasScope(authentication, 'ok')")
		public String ok() {
			return "ok";
		}

		@GetMapping("/authenticated")
		public String okay(@AuthenticationPrincipal Authentication auth) {
			if ( auth instanceof JwtAccessTokenAuthenticationToken ) {
				return ((JwtAccessTokenAuthenticationToken) auth).getJwt().getSubject();
			}
			return null;
		}
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	class WebSecurityConfig extends WebSecurityConfigurerAdapter {
		@Value("${jwt.verifying.key}")
		KeyProvider<PublicKey> verify;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			resourceServer(http)
					.jwt()
							.signature().keys(this.verify)
							.validators(
									timestamps().areValidWithin(30).seconds(),
									audience().isOneOf("validator-app", "simple-app"),
									issuer().is("https://uaa"),
									claim("custom").is("harold")).and()
					.and()
			.authorizeRequests()
					.anyRequest().authenticated();
		}

		protected ResourceServerConfigurer<HttpSecurity> resourceServer(HttpSecurity http) throws Exception {
			return http.apply(new ResourceServerConfigurer<>());
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(ValidatorsApplication.class, args);
	}
}
