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
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver.ResourceServerConfigurer;
import org.springframework.security.oauth2.jwt.KeyProvider;

import java.security.PublicKey;

import static org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver.ValidatorConfigurer.audience;
import static org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver.ValidatorConfigurer.claim;
import static org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver.ValidatorConfigurer.issuer;
import static org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver.ValidatorConfigurer.timestamps;

@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ValidatorsSecurityConfig extends WebSecurityConfigurerAdapter {
	@Value("${jwt.verifying.key}")
	KeyProvider<PublicKey> verify;

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		// @formatter:off
		http
			.apply(new ResourceServerConfigurer<>())
				.jwt()
					.signature().keys(this.verify)
					.validators(
						timestamps().areValidWithin(30).seconds(),
						audience().in("validator-app", "simple-app"),
						issuer().is("https://uaa"),
						claim("custom").is("harold")).and()
					.and()
			.authorizeRequests()
				.anyRequest().authenticated();
		// @formatter:on
	}
}
