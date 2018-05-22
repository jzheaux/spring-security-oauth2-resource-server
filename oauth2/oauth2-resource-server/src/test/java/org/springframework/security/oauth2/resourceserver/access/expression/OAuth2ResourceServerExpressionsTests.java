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
package org.springframework.security.oauth2.resourceserver.access.expression;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.resourceserver.authentication.JwtAccessTokenAuthenticationProvider;
import org.springframework.security.oauth2.resourceserver.authentication.JwtAccessTokenValidator;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenAuthenticationFilter;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Josh Cummings
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SecurityTestExecutionListeners
public class OAuth2ResourceServerExpressionsTests {
	AnnotationConfigWebApplicationContext context;
	MockMvc mvc;

	OAuth2AuthenticationSupport authentication = new OAuth2AuthenticationSupport();

	@After
	public void clear() {
		this.authentication.clear();
	}

	@Test
	public void attributeWhenAttributeIsPresentThenReturned() {
		Authentication authentication =
				this.authentication.attribute("scope", "permission").authenticate();

		OAuth2ResourceServerExpressions expressions = new OAuth2ResourceServerExpressions();

		assertThat(expressions.attribute(authentication, "scope")).isEqualTo("permission");
	}

	@Test
	public void attributeWhenAttributeIsMissingThenNull() {
		Authentication authentication = this.authentication.authenticate();

		OAuth2ResourceServerExpressions expressions = new OAuth2ResourceServerExpressions();

		assertThat(expressions.attribute(authentication, "scope")).isEqualTo(null);
	}

	private AnnotationConfigApplicationContext context(Class<?>... classesToRegister) {
		AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
		context.register(classesToRegister);
		context.refresh();

		return context;
	}

	@Test
	@WithMockUser
	public void evaluateWhenNotOAuthAuthenticatedThenDenies() {
		ApplicationContext context = context(OAuth2ExpressionConfig.class, MethodSecurityService.class);

		MethodSecurityService service = context.getBean(MethodSecurityService.class);

		assertThatThrownBy(() -> service.needsExactlyPermissionScope())
				.isInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void evaluateWhenIssuerMatchesThenAllows() {
		this.authentication.attribute("issuer", "www.springframework.org").authenticate();

		ApplicationContext context = context(OAuth2ExpressionConfig.class, MethodSecurityService.class);

		MethodSecurityService service = context.getBean(MethodSecurityService.class);

		service.needsIssuerEndingInSpecificDomain();
	}

	@Test
	public void evaluateWhenHasRequiredScopeClaimThenPasses() {
		this.authentication.attribute("scope", "permission").authenticate();

		ApplicationContext context = context(OAuth2ExpressionConfig.class, MethodSecurityService.class);

		MethodSecurityService service = context.getBean(MethodSecurityService.class);

		service.needsExactlyPermissionScope();
	}

	@Test
	public void evaluateWhenMissingRequiredScopeClaimThenDenies() {
		this.authentication.authenticate();

		ApplicationContext context = context(OAuth2ExpressionConfig.class, MethodSecurityService.class);

		MethodSecurityService service = context.getBean(MethodSecurityService.class);

		assertThatThrownBy(() -> service.needsExactlyPermissionScope())
				.isInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void evaluateWhenConfiguredForAnyScopeButRequestDoesNotHaveAnyThenDenies() {
		this.authentication.attribute("scope", "permission.dance").authenticate();

		ApplicationContext context = context(OAuth2ExpressionConfig.class, MethodSecurityService.class);

		MethodSecurityService service = context.getBean(MethodSecurityService.class);

		assertThatThrownBy(() -> service.needsOneOfTwoScopes())
				.isInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void evaluateWhenConfiguredForAnyScopeAndRequestHasOneThenAllows() {
		this.authentication.attribute("scope", "permission.read").authenticate();

		ApplicationContext context = context(OAuth2ExpressionConfig.class, MethodSecurityService.class);

		MethodSecurityService service = context.getBean(MethodSecurityService.class);

		service.needsOneOfTwoScopes();
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class OAuth2ExpressionConfig {
		/**
		 * This would ultimately be supplied by an OAuth2 configurer
		 */
		@Bean
		public OAuth2Expressions oauth2() {
			return new OAuth2ResourceServerExpressions();
		}
	}

	public static class MethodSecurityService {
		@PreAuthorize("@oauth2.attribute(authentication, 'issuer') matches '.*springframework.org'")
		public String needsIssuerEndingInSpecificDomain() {
			return "foo";
		}

		@PreAuthorize("@oauth2.attribute(authentication, 'scope') == 'permission'")
		public String needsExactlyPermissionScope() {
			return "foo";
		}

		@PreAuthorize("@oauth2.attribute(authentication, 'scope') matches 'permission.(read|write)'")
		public String needsOneOfTwoScopes() {
			return "foo";
		}
	}

	@Test
	public void performWhenIssuerMatchesThenAllows() throws Exception {
		this.register(WebSecurityOAuth2ExpressionConfig.class, WebSecurityController.class);

		this.mvc.perform(
				get("/needsIssuerEndingInSpecificDomain")
						.header("Authorization", "Bearer token"))
				.andExpect(content().string("ok"));
	}

	@Test
	public void permissionWhenMissingRequiredScopeClaimThenDenies() throws Exception {
		this.register(WebSecurityOAuth2ExpressionConfig.class, WebSecurityController.class);

		this.mvc.perform(
			get("/needsExactlyPermissionScope")
				.header("Authorization", "Bearer token"))
			.andExpect(status().isForbidden());
	}

	@Test
	public void performWhenConfiguredForAnyScopeAndRequestHasOneThenAllows()
		throws Exception {

		this.register(WebSecurityOAuth2ExpressionConfig.class, WebSecurityController.class);

		this.mvc.perform(
				get("/needsOneOfTwoScopes")
					.header("Authorization", "Bearer token"))
				.andExpect(content().string("ok"));
	}

	@EnableWebSecurity
	public static class WebSecurityOAuth2ExpressionConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.addFilterAfter(
					bearerTokenAuthenticationFilter(),
					BasicAuthenticationFilter.class)
				.exceptionHandling()
				.authenticationEntryPoint(restAuthenticationEntryPoint()).and()
				.authorizeRequests()
					.antMatchers("/needsIssuerEndingInSpecificDomain")
						.access
							("@oauth2.attribute(authentication, 'iss') matches '.*springframework.org'")
					.antMatchers("/needsExactlyPermissionScope")
						.access
							("@oauth2.hasScope(authentication, 'permission')")
					.antMatchers("/needsOneOfTwoScopes")
						.access
							("@oauth2.hasAnyScope(authentication, 'permission.read', 'permission.write')")
					.and()
				.csrf().disable();

			super.configure(http);
		}

		@Bean
		public OAuth2Expressions oauth2() {
			return new OAuth2ResourceServerExpressions();
		}

		BearerTokenAuthenticationFilter bearerTokenAuthenticationFilter() {
			return new BearerTokenAuthenticationFilter(authenticationManager());
		}

		@Bean
		public AuthenticationManager authenticationManager() {
			return new ProviderManager(
					Arrays.asList(oauthResourceAuthenticationProvider())
			);
		}

		@Bean
		AuthenticationProvider oauthResourceAuthenticationProvider() {
			return new JwtAccessTokenAuthenticationProvider
					(jwtDecoder(), new JwtAccessTokenValidator());
		}

		@Bean
		JwtDecoder jwtDecoder() {
			return token -> {
					Map<String, Object> headers = new HashMap<>();
					headers.put("alg", JwsAlgorithms.RS256);

					Map<String, Object> claims = new HashMap<>();
					claims.put(JwtClaimNames.ISS, "www.springframework.org");
					claims.put("scope", "permission.read permission.write");

					return new Jwt("token",
							Instant.MIN,
							Instant.MAX,
							headers,
							claims);
			};
		}

		@Bean
		AuthenticationEntryPoint restAuthenticationEntryPoint() {
			return new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);
		}

	}

	@RestController
	public static class WebSecurityController {
		@GetMapping("/needsIssuerEndingInSpecificDomain")
		public String needsIssuerEndingInSpecificDomain() { return "ok"; }

		@GetMapping("/needsExactlyPermissionScope")
		public String needsExactlyPermissionScope() { return "ok"; }

		@GetMapping("/needsOneOfTwoScopes")
		public String needsOneOfTwoScopes() { return "ok"; }
	}

	private void register(Class<?>... classes) {
		this.context = new AnnotationConfigWebApplicationContext();
		this.context.register(classes);
		this.context.setServletContext(new MockServletContext());
		this.context.setServletConfig(new MockServletConfig());
		this.context.refresh();
		this.mvc = MockMvcBuilders.webAppContextSetup(this.context)
						.apply(springSecurity()).build();
	}
}
