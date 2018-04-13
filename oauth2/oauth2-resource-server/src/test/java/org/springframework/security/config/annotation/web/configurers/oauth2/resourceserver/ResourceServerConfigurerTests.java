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
package org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver;

import okhttp3.HttpUrl;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jose.jwk.JwkSetBuilder;
import org.springframework.security.oauth2.jose.jws.JwsBuilder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.security.oauth2.resourceserver.authentication.JwtEncodedOAuth2AccessTokenAuthenticationProvider;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Josh Cummings
 */
public class ResourceServerConfigurerTests {

	private AnnotationConfigWebApplicationContext context;

	private MockMvc mvc;
	private MockWebServer server;

	@Test
	public void performWhenBearerIsSignedWithJwkOverRsaThenAccessIsAuthorized()
			throws Exception {

		this.register(WebServerConfig.class, RsaConfig.class);

		JwkSetBuilder good = JwkSetBuilder.withRsa("good");

		String authority = JwsBuilder.withAlgorithm("RS256")
				.expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
				.scope("permission.read")
				.signWithAny(good).build();

		this.setupJwks(good);

		this.mvc.perform(bearer(get("/"), authority))
				.andExpect(content().string("OK"));

		assertThat(this.server.getRequestCount()).isEqualTo(1);
	}

	@Test
	public void performWhenBearerIsSignedWithMissingJwkOverRsaThenNotAuthorized()
			throws Exception {

		this.register(WebServerConfig.class, RsaConfig.class);

		JwkSetBuilder bad = JwkSetBuilder.withRsa("bad");
		JwkSetBuilder good = JwkSetBuilder.withRsa("good");

		String authority = JwsBuilder.withAlgorithm("RS256").signWithAny(bad).build();

		this.setupJwks(good);

		this.mvc.perform(bearer(get("/"), authority))
				.andExpect(status().isUnauthorized());

		assertThat(this.server.getRequestCount()).isEqualTo(2);
	}

	@Test
	public void performWhenBearerIsSignedButServerHasNoJwksThenNotAuthorized()
			throws Exception {

		this.register(WebServerConfig.class, RsaConfig.class);

		JwkSetBuilder empty = JwkSetBuilder.empty();
		JwkSetBuilder good = JwkSetBuilder.withRsa("good");

		String authority = JwsBuilder.withAlgorithm("RS256").signWithAny(good).build();

		this.setupJwks(empty);

		this.mvc.perform(bearer(get("/"), authority))
				.andExpect(status().isUnauthorized());

		assertThat(this.server.getRequestCount()).isEqualTo(2);
	}

	@EnableWebSecurity
	public static class RsaConfig extends WithResourceServerConfigurerAdapter {
		@Autowired
		MockWebServer server;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			super.configure(http);

			http
					.authorizeRequests().anyRequest()
					.access("authentication.hasAttribute('scope', 'permission.read')");
		}

		@Bean
		protected AuthenticationProvider oauth2AuthenticationProvider() {
			return new JwtEncodedOAuth2AccessTokenAuthenticationProvider(this.jwtDecoder());
		}

		@Bean
		JwtDecoder jwtDecoder() {
			HttpUrl url = this.server.url("/.well-known/jwks.json");

			return new NimbusJwtDecoderJwkSupport(
					url.toString(),
					"RS256");
		}

	}

	@Test
	public void performWhenBearerIsSignedWithJwkOverEcdsaThenAuthorized()
			throws Exception {

		this.register(WebServerConfig.class, EcConfig.class);

		JwkSetBuilder good = JwkSetBuilder.withEc("good");

		String authority = JwsBuilder.withAlgorithm("ES512")
				.expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
				.scope("permission.read")
				.signWithAny(good).build();

		this.setupJwks(good);

		this.mvc.perform(bearer(get("/"), authority))
				.andExpect(content().string("OK"));

		assertThat(this.server.getRequestCount()).isEqualTo(1);
	}

	@EnableWebSecurity
	public static class EcConfig extends WithResourceServerConfigurerAdapter {
		@Autowired MockWebServer server;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			super.configure(http);

			http
					.authorizeRequests().anyRequest()
					.access("authentication.hasAttribute('scope', 'permission.read')");
		}

		@Bean
		protected AuthenticationProvider oauth2AuthenticationProvider() {
			return new JwtEncodedOAuth2AccessTokenAuthenticationProvider(this.jwtDecoder());
		}

		@Bean
		JwtDecoder jwtDecoder() {
			HttpUrl url = this.server.url("/.well-known/jwks.json");

			return new NimbusJwtDecoderJwkSupport(
					url.toString(),
					"ES512");
		}

	}

	public static abstract class WithResourceServerConfigurerAdapter extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.addFilterAfter(
							new BearerTokenAuthenticationFilter(authenticationManager()),
							BasicAuthenticationFilter.class)
					.authenticationProvider(oauth2AuthenticationProvider())
					.exceptionHandling().and()
					.csrf().disable();
		}

		protected abstract AuthenticationProvider oauth2AuthenticationProvider();
	}

	@Configuration
	public static class WebServerConfig {
		@RestController
		public class SecuredController {
			@GetMapping("/")
			public String ok() {
				return "OK";
			}
		}

		@Bean
		MockWebServer server() {
			return new MockWebServer();
		}
	}

	private MockHttpServletRequestBuilder bearer(MockHttpServletRequestBuilder mock, String authority) {
		return mock.header("Authorization", "Bearer " + authority);
	}

	private void setupJwks(JwkSetBuilder builder) {
			MockResponse response = new MockResponse()
					.setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
					.setBody(builder.build());

			this.server.enqueue(response);
		this.server.enqueue(response);

	}

	private void register(Class<?>... classes) {
		this.context = new AnnotationConfigWebApplicationContext();
		this.context.register(classes);
		this.context.setServletContext(new MockServletContext());
		this.context.setServletConfig(new MockServletConfig());
		this.context.refresh();
		this.mvc = MockMvcBuilders.webAppContextSetup(this.context)
				.apply(springSecurity()).build();

		this.server = this.context.getBean(MockWebServer.class);
	}
}
