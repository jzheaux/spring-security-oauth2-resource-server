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
package org.springframework.security.oauth2.resourceserver.authorization;

import org.junit.After;
import org.junit.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests prototyping OAuth 2.0 Resource Server authorization using SpEL as the mechanism.
 *
 * @author Joe Grandja
 */
public class OAuth2ResourceServerAuthorizationTests {
	private AnnotationConfigWebApplicationContext context;
	private MockMvc mockMvc;

	@After
	public void cleanup() {
		if (this.context != null) {
			this.context.close();
		}
	}

	@Test
	public void requestWhenJwtAccessTokenHasScopeThenAccessGranted() throws Exception {
		this.register(ScopeSecurityConfig.class, WebConfig.class);

		Map<String, Object> claims = new HashMap<>();
		claims.put("scp", new String[] {"read", "write"});

		// NOTE:
		// The 'Jwt' AuthenticationProvider is responsible for parsing the Jwt
		// and mapping the scope(s) to authorities
		JwtAccessTokenAuthenticationToken jwtAccessTokenAuthentication = this.createJwtAccessTokenAuthentication(
				claims, AuthorityUtils.createAuthorityList("SCOPE_READ", "SCOPE_WRITE"));

		this.mockMvc.perform(get("/resources/resource1").with(authentication(jwtAccessTokenAuthentication)))
				.andExpect(status().isOk());
	}

	@Test
	public void requestWhenOpaqueAccessTokenHasScopeThenAccessGranted() throws Exception {
		this.register(ScopeSecurityConfig.class, WebConfig.class);

		Map<String, Object> attributes = new HashMap<>();
		attributes.put("scope", "read write");		// 'scope' is an (optional) attribute of the Introspection Response

		// NOTE:
		// The 'Opaque' AuthenticationProvider is responsible for requesting the token attributes
		// from the OAuth 2.0 Token Introspection Endpoint and mapping the scope(s) to authorities
		IntrospectedAccessTokenAuthenticationToken introspectedAccessTokenAuthentication =
				this.createIntrospectedAccessTokenAuthentication(
						attributes, AuthorityUtils.createAuthorityList("SCOPE_READ", "SCOPE_WRITE"));

		this.mockMvc.perform(get("/resources/resource1").with(authentication(introspectedAccessTokenAuthentication)))
				.andExpect(status().isOk());
	}

	@EnableWebSecurity
	static class ScopeSecurityConfig extends WebSecurityConfigurerAdapter {

		// @formatter:off
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.antMatchers("/resources/resource1").access("#oauth2.hasAnyScope('READ', 'WRITE')")
					.expressionHandler(getExpressionHandler(http))	// NOTE: This will be configured in ResourceServerSecurityConfigurer
					.and()
				.authenticationProvider(new OAuth2AccessTokenAuthenticationProvider());
		}
		// @formatter:on
	}

	@Test
	public void requestWhenJwtAccessTokenHasScopeAndValidIssuerThenAccessGranted() throws Exception {
		this.register(ScopeAndIssuerVerifierSecurityConfig.class, WebConfig.class);

		Map<String, Object> claims = new HashMap<>();
		claims.put("scp", new String[] {"read", "write"});
		claims.put("iss", "https://example.provider.com");

		// NOTE:
		// The 'Jwt' AuthenticationProvider is responsible for parsing the Jwt
		// and mapping the scope(s) to authorities
		JwtAccessTokenAuthenticationToken jwtAccessTokenAuthentication = this.createJwtAccessTokenAuthentication(
				claims, AuthorityUtils.createAuthorityList("SCOPE_READ", "SCOPE_WRITE"));

		this.mockMvc.perform(get("/resources/resource1").with(authentication(jwtAccessTokenAuthentication)))
				.andExpect(status().isOk());
	}

	@EnableWebSecurity
	static class ScopeAndIssuerVerifierSecurityConfig extends WebSecurityConfigurerAdapter {

		// @formatter:off
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.antMatchers("/resources/resource1").access("#oauth2.hasAnyScope('READ', 'WRITE') and #oauth2.verify(@issuerVerifier)")
					.expressionHandler(getExpressionHandler(http))	// NOTE: This will be configured in ResourceServerSecurityConfigurer
					.and()
				.authenticationProvider(new OAuth2AccessTokenAuthenticationProvider());
		}
		// @formatter:on

		// A @Bean that verifies the Issuer claim
		// NOTE: OAuth2TokenVerifier provides an extension point for users requiring custom claims/attributes verification
		@Bean("issuerVerifier")
		public OAuth2TokenVerifier issuerVerifier() {
			return tokenAttributes -> tokenAttributes.containsKey("iss") && tokenAttributes.get("iss").equals("https://example.provider.com");
		}
	}

	@Test
	public void requestWhenOpaqueAccessTokenHasAuthorityThenAccessGranted() throws Exception {
		this.register(AuthoritySecurityConfig.class, WebConfig.class);

		Map<String, Object> attributes = new HashMap<>();
		attributes.put("scope", "read write");		// 'scope' is an (optional) attribute of the Introspection Response

		// NOTE:
		// The 'Opaque' AuthenticationProvider is responsible for requesting the token attributes
		// from the OAuth 2.0 Token Introspection Endpoint and mapping the scope(s) to authorities
		IntrospectedAccessTokenAuthenticationToken introspectedAccessTokenAuthentication =
				this.createIntrospectedAccessTokenAuthentication(
						attributes, AuthorityUtils.createAuthorityList("SCOPE_READ", "SCOPE_WRITE"));

		this.mockMvc.perform(get("/resources/resource1").with(authentication(introspectedAccessTokenAuthentication)))
				.andExpect(status().isOk());
	}

	@EnableWebSecurity
	static class AuthoritySecurityConfig extends WebSecurityConfigurerAdapter {

		// @formatter:off
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.antMatchers("/resources/resource1").access("#oauth2.hasAnyAuthority('SCOPE_READ', 'SCOPE_WRITE')")
					.expressionHandler(getExpressionHandler(http))	// NOTE: This will be configured in ResourceServerSecurityConfigurer
					.and()
				.authenticationProvider(new OAuth2AccessTokenAuthenticationProvider());
		}
		// @formatter:on
	}

	private static SecurityExpressionHandler<FilterInvocation> getExpressionHandler(HttpSecurity http) {
		OAuth2ResourceSecurityExpressionHandler expressionHandler = new OAuth2ResourceSecurityExpressionHandler();

		// NOTE:
		// The code below was copied from ExpressionUrlAuthorizationConfigurer.getExpressionHandler()
		// Need to determine which part(s) of the code is required
		AuthenticationTrustResolver trustResolver = http.getSharedObject(AuthenticationTrustResolver.class);
		if (trustResolver != null) {
			expressionHandler.setTrustResolver(trustResolver);
		}
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);
		if (context != null) {
			String[] roleHiearchyBeanNames = context.getBeanNamesForType(RoleHierarchy.class);
			if (roleHiearchyBeanNames.length == 1) {
				expressionHandler.setRoleHierarchy(context.getBean(roleHiearchyBeanNames[0], RoleHierarchy.class));
			}
			String[] grantedAuthorityDefaultsBeanNames = context.getBeanNamesForType(GrantedAuthorityDefaults.class);
			if (grantedAuthorityDefaultsBeanNames.length == 1) {
				GrantedAuthorityDefaults grantedAuthorityDefaults =
						context.getBean(grantedAuthorityDefaultsBeanNames[0], GrantedAuthorityDefaults.class);
				expressionHandler.setDefaultRolePrefix(grantedAuthorityDefaults.getRolePrefix());
			}
			String[] permissionEvaluatorBeanNames = context.getBeanNamesForType(PermissionEvaluator.class);
			if (permissionEvaluatorBeanNames.length == 1) {
				PermissionEvaluator permissionEvaluator =
						context.getBean(permissionEvaluatorBeanNames[0], PermissionEvaluator.class);
				expressionHandler.setPermissionEvaluator(permissionEvaluator);
			}
		}

		// TODO
//			expressionHandler = http.postProcess(expressionHandler);
		expressionHandler.setApplicationContext(context);

		return expressionHandler;
	}

	private JwtAccessTokenAuthenticationToken createJwtAccessTokenAuthentication(
			Map<String, Object> claims, Collection<? extends GrantedAuthority> authorities) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plusSeconds(300);
		Map<String, Object> headers = new HashMap<>();
		headers.put("header1", "value1");

		Jwt jwt = new Jwt("jwt-token-value", issuedAt, expiresAt, headers, claims);

		return new JwtAccessTokenAuthenticationToken(jwt, authorities);
	}

	private IntrospectedAccessTokenAuthenticationToken createIntrospectedAccessTokenAuthentication(
			Map<String, Object> attributes, Collection<? extends GrantedAuthority> authorities) {

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plusSeconds(300);

		IntrospectedOAuth2AccessToken introspectedAccessToken = new IntrospectedOAuth2AccessToken(
				OAuth2AccessToken.TokenType.BEARER, "introspected-token-value", issuedAt, expiresAt, attributes);

		return new IntrospectedAccessTokenAuthenticationToken(introspectedAccessToken, authorities);
	}

	private void register(Class<?>... classes) {
		this.context = new AnnotationConfigWebApplicationContext();
		this.context.register(classes);
		this.context.setServletContext(new MockServletContext());
		this.context.setServletConfig(new MockServletConfig());
		this.context.refresh();
		this.mockMvc = MockMvcBuilders.webAppContextSetup(this.context)
				.apply(springSecurity()).build();
	}

	@EnableWebMvc
	static class WebConfig {

		@RestController
		@RequestMapping("/resources")
		public class ResourcesController {

			@GetMapping("/resource1")
			public String resource1() {
				return "resource1";
			}

			@GetMapping("/resource2")
			public String resource2() {
				return "resource2";
			}

			@GetMapping("/resource3")
			public String resource3() {
				return "resource3";
			}
		}
	}

	public abstract class AbstractOAuth2AccessTokenAuthenticationToken extends AbstractAuthenticationToken {
		private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
		private final Map<String, Object> attributes;

		protected AbstractOAuth2AccessTokenAuthenticationToken(Map<String, Object> attributes) {
			this(attributes, AuthorityUtils.createAuthorityList("OAUTH2_ACCESS_TOKEN"));
		}

		protected AbstractOAuth2AccessTokenAuthenticationToken(Map<String, Object> attributes, Collection<? extends GrantedAuthority> authorities) {
			super(authorities);
			Assert.notEmpty(attributes, "attributes cannot be empty");
			this.attributes = Collections.unmodifiableMap(attributes);
		}

		@Override
		public Object getPrincipal() {
			return "";
		}

		@Override
		public Object getCredentials() {
			return "";
		}

		public final Map<String, Object> getAttributes() {
			return this.attributes;
		}
	}

	public class JwtAccessTokenAuthenticationToken extends AbstractOAuth2AccessTokenAuthenticationToken {
		private final Jwt jwt;

		public JwtAccessTokenAuthenticationToken(Jwt jwt) {
			this(jwt, AuthorityUtils.createAuthorityList("OAUTH2_ACCESS_TOKEN_JWT"));
		}

		public JwtAccessTokenAuthenticationToken(Jwt jwt, Collection<? extends GrantedAuthority> authorities) {
			super(jwt.getClaims(), authorities);
			this.jwt = jwt;
			this.setAuthenticated(true);
		}

		public final Jwt getJwt() {
			return this.jwt;
		}
	}

	public class IntrospectedOAuth2AccessToken extends OAuth2AccessToken {
		private final Map<String, Object> attributes;		// Attributes from Introspection Response

		public IntrospectedOAuth2AccessToken(TokenType tokenType, String tokenValue, Instant issuedAt,
												Instant expiresAt, Map<String, Object> attributes) {
			this(tokenType, tokenValue, issuedAt, expiresAt, Collections.emptySet(), attributes);
		}

		public IntrospectedOAuth2AccessToken(TokenType tokenType, String tokenValue, Instant issuedAt,
												Instant expiresAt, Set<String> scopes, Map<String, Object> attributes) {
			super(tokenType, tokenValue, issuedAt, expiresAt, scopes);
			Assert.notEmpty(attributes, "attributes cannot be empty");
			this.attributes = attributes;
		}

		public final Map<String, Object> getAttributes() {
			return this.attributes;
		}
	}

	public class IntrospectedAccessTokenAuthenticationToken extends AbstractOAuth2AccessTokenAuthenticationToken {
		private final IntrospectedOAuth2AccessToken introspectedAccessToken;

		public IntrospectedAccessTokenAuthenticationToken(IntrospectedOAuth2AccessToken introspectedAccessToken) {
			this(introspectedAccessToken, AuthorityUtils.createAuthorityList("OAUTH2_ACCESS_TOKEN"));
		}

		public IntrospectedAccessTokenAuthenticationToken(IntrospectedOAuth2AccessToken introspectedAccessToken,
															Collection<? extends GrantedAuthority> authorities) {
			super(introspectedAccessToken.getAttributes(), authorities);
			this.introspectedAccessToken = introspectedAccessToken;
			this.setAuthenticated(true);
		}

		public final IntrospectedOAuth2AccessToken getIntrospectedAccessToken() {
			return this.introspectedAccessToken;
		}
	}

	public interface OAuth2TokenVerifier {

		// TODO Return boolean OR void and throw Exception?
		boolean verify(Map<String, Object> tokenAttributes);

	}

	// This needs to be split up into 2 implementations:
	// 1) Jwt AuthenticationProvider
	// 2) Opaque AuthenticationProvider - for OAuth 2.0 Token Introspection
	public static class OAuth2AccessTokenAuthenticationProvider implements AuthenticationProvider {

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			return authentication;
		}

		@Override
		public boolean supports(Class<?> authentication) {
			return AbstractOAuth2AccessTokenAuthenticationToken.class.isAssignableFrom(authentication);
		}
	}

	public interface OAuth2ResourceSecurityExpressionOperations {

		boolean hasScope(String scope);

		boolean hasAnyScope(String... scopes);

		boolean verify(OAuth2TokenVerifier verifier);

	}

	// NOTE: Extending AbstractSecurityExpressionHandler<FilterInvocation> instead might be sufficient
	public static class OAuth2ResourceSecurityExpressionHandler extends DefaultWebSecurityExpressionHandler {

		@Override
		protected SecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication, FilterInvocation fi) {
			OAuth2ResourceSecurityExpressionRoot root = new OAuth2ResourceSecurityExpressionRoot(authentication);
			root.setPermissionEvaluator(this.getPermissionEvaluator());
			root.setTrustResolver(new AuthenticationTrustResolverImpl());
			root.setRoleHierarchy(this.getRoleHierarchy());
			root.setDefaultRolePrefix("ROLE_");
			return root;
		}

		@Override
		protected StandardEvaluationContext createEvaluationContextInternal(Authentication authentication, FilterInvocation invocation) {
			StandardEvaluationContext evaluationContext = super.createEvaluationContextInternal(authentication, invocation);

			// TODO This is getting created 2x...here and in createSecurityExpressionRoot() - need to optimize
			OAuth2ResourceSecurityExpressionOperations oauth2 = new OAuth2ResourceSecurityExpressionRoot(authentication);
			evaluationContext.setVariable("oauth2", oauth2);

			return evaluationContext;
		}
	}

	public static class OAuth2ResourceSecurityExpressionRoot extends SecurityExpressionRoot
			implements OAuth2ResourceSecurityExpressionOperations {

		public OAuth2ResourceSecurityExpressionRoot(Authentication authentication) {
			super(authentication);
			this.setDefaultRolePrefix("SCOPE_");
		}

		@Override
		public boolean hasScope(String scope) {
			return this.hasRole(scope);
		}

		@Override
		public boolean hasAnyScope(String... scopes) {
			return this.hasAnyRole(scopes);
		}

		@Override
		public boolean verify(OAuth2TokenVerifier verifier) {
			return verifier.verify(getAccessTokenAttributes());
		}

		private Map<String, Object> getAccessTokenAttributes() {
			Map<String, Object> tokenAttributes = Collections.emptyMap();
			if (AbstractOAuth2AccessTokenAuthenticationToken.class.isAssignableFrom(this.getAuthentication().getClass())) {
				tokenAttributes = ((AbstractOAuth2AccessTokenAuthenticationToken) this.getAuthentication()).getAttributes();
			}
			return tokenAttributes;
		}
	}
}
