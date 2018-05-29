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

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.AuthoritiesExtractor;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.KeyProvider;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderLocalKeySupport;
import org.springframework.security.oauth2.jwt.SingleKeyProvider;
import org.springframework.security.oauth2.resourceserver.access.expression.OAuth2Expressions;
import org.springframework.security.oauth2.resourceserver.access.expression.OAuth2ResourceServerExpressions;
import org.springframework.security.oauth2.resourceserver.authentication.JwtAccessTokenAuthenticationProvider;
import org.springframework.security.oauth2.resourceserver.authentication.JwtAccessTokenValidator;
import org.springframework.security.oauth2.resourceserver.authentication.JwtTokenValidator;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenRequestMatcher;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenResolver;
import org.springframework.security.oauth2.resourceserver.web.DefaultBearerTokenResolver;
import org.springframework.security.oauth2.resourceserver.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

/**
 * Example configuration:
 *
 * oauth2().resourceServer()
 *     .jwt()
 *         .signature().keys("http://jwk.url")
 *
 * Or:
 *
 * oauth2().resourceServer()
 *         .jwt(auth0AccessTokenProcessor())
 *         .validators(some(), custom(), validators())
 *
 * @author Josh Cummings
 */
public final class ResourceServerConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractHttpConfigurer<ResourceServerConfigurer<H>, H> {

	private BearerTokenResolver resolver;
	private JwtAccessTokenFormatConfigurer jwtAccessTokenFormatConfigurer;

	public ResourceServerConfigurer() {
	}

	public ResourceServerConfigurer<H> bearerTokenResolver(BearerTokenResolver resolver) {
		this.resolver = resolver;
		return this;
	}

	public NeedsSignatureJwtAccessTokenFormatConfigurer jwt() {
		if ( this.jwtAccessTokenFormatConfigurer == null ) {
			this.jwtAccessTokenFormatConfigurer = new NeedsSignatureJwtAccessTokenFormatConfigurer();
		}

		//TODO don't forget the ClassCastException risk inherent in this design
		return (NeedsSignatureJwtAccessTokenFormatConfigurer) this.jwtAccessTokenFormatConfigurer;
	}

	public JwtAccessTokenFormatConfigurer jwt(JwtDecoder decoder) {
		if ( this.jwtAccessTokenFormatConfigurer == null ) {
			this.jwtAccessTokenFormatConfigurer = new JwtAccessTokenFormatConfigurer(decoder);
		}


		return this.jwtAccessTokenFormatConfigurer;
	}

	public class JwtAccessTokenFormatConfigurer {
		protected JwtDecoderConfigurer jwtDecoder = new JwtDecoderConfigurer();
		private Collection<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
		private AuthoritiesExtractor extractor = (authentication) -> Collections.emptyList();
		private String scopeAttributeName;

		public JwtAccessTokenFormatConfigurer() {}

		public JwtAccessTokenFormatConfigurer(JwtDecoder decoder) {
			this.jwtDecoder.decoder(decoder);
		}

		public JwtAccessTokenFormatConfigurer authoritiesExtractor(AuthoritiesExtractor extractor) {
			this.extractor = extractor;
			return this;
		}

		public JwtAccessTokenFormatConfigurer scopeAttributeName(String scopeAttributeName) {
			this.scopeAttributeName = scopeAttributeName;
			return this;
		}

		public JwtAccessTokenFormatConfigurer validator(OAuth2TokenValidator<Jwt> validator) {
			this.validators.add(validator);
			return this;
		}

		public ResourceServerConfigurer<H> and() {
			return ResourceServerConfigurer.this;
		}
	}

	public class NeedsSignatureJwtAccessTokenFormatConfigurer
		extends JwtAccessTokenFormatConfigurer {

		protected String algorithm = JwsAlgorithms.RS256;

		public NeedsSignatureJwtAccessTokenFormatConfigurer algorithm(String algorithm) {
			this.algorithm = algorithm;
			return this;
		}

		public SignatureVerificationConfigurer signature() {
			return new SignatureVerificationConfigurer(this);
		}
	}

	public class SignatureVerificationConfigurer {
		private NeedsSignatureJwtAccessTokenFormatConfigurer parent;

		public SignatureVerificationConfigurer(NeedsSignatureJwtAccessTokenFormatConfigurer parent) {
			this.parent = parent;
		}

		public JwtAccessTokenFormatConfigurer keys(UrlConfigurer configurer) {
			this.parent.jwtDecoder.decoder(
					new NimbusJwtDecoderJwkSupport(configurer.url.toString(), this.parent.algorithm));

			return this.parent;
		}

		public JwtAccessTokenFormatConfigurer keys(KeyProvider provider) {
			this.parent.jwtDecoder.decoder(
					new NimbusJwtDecoderLocalKeySupport(provider, this.parent.algorithm));

			return this.parent;
		}

		public JwtAccessTokenFormatConfigurer key(Key key) {
			SingleKeyProvider provider = () -> key;

			this.parent.jwtDecoder.decoder(
					new NimbusJwtDecoderLocalKeySupport(provider, this.parent.algorithm));

			return this.parent;
		}
	}

	public class JwtDecoderConfigurer {
		private JwtDecoder jwtDecoder;

		public JwtDecoderConfigurer decoder(JwtDecoder decoder) {
			this.jwtDecoder = decoder;
			return this;
		}

		public JwtDecoder decoder() {
			return this.jwtDecoder;
		}
	}

	public static class UrlConfigurer {
		URL url;
		Long readTimeout;
		Long connectTimeout;

		public static UrlConfigurer url(String location) {
			UrlConfigurer configurer = new UrlConfigurer();
			try {
				configurer.url = new URL(location);
			} catch ( MalformedURLException malformed ) {
				throw new IllegalArgumentException(malformed);
			}
			return configurer;
		}

		public UrlConfigurer readTimeout(Long readTimeout) {
			this.readTimeout = readTimeout;
			return this;
		}

		public UrlConfigurer connectTimeout(Long connectTimeout) {
			this.connectTimeout = connectTimeout;
			return this;
		}
	}

	@Override
	public void setBuilder(H builder) {
		super.setBuilder(builder);

		/*
			TODO: This still isn't ideal since now it depends on the order in
			which the DSL methods are called. For example, if
			http.sessionManagement().sessionCreationPolicy is called by the user before
			http.oauth2().resourceServer() is, then this will override the user's
			configuration.

			We cannot simply set values for SecurityContextRepository and RequestCache
			because SessionManagementConfigurer won't override them with the user's
			configs (checks for null before setting).
		 */
		sessionManagement(builder).sessionCreationPolicy(SessionCreationPolicy.NEVER);

	}

	@Override
	public void init(H http) throws Exception {
		/*
			TODO: Based on the description in SecurityConfigurer, I believe this is incorrect;
			however if I place the same code in configure, then the dependent beans seem to already
			have been configured. This way works, but it likely doesn't play nicely with other
			configurers.

			See my notes below that point out various challenges.
		 */

		ApplicationContext context = http.getSharedObject(ApplicationContext.class);

		/*
			TODO: Doing bearerTokenResolver this early because the csrf configuration
			currently needs to also be this early until I figure out how to tell inside
			configure() whether or not the user has specified his own CSRF RequestMatcher
		 */
		if ( this.resolver == null ) {
			Map<String, BearerTokenResolver> resolvers =
					BeanFactoryUtils.beansOfTypeIncludingAncestors(context, BearerTokenResolver.class);

			if ( !resolvers.isEmpty() ) {
				this.resolver = resolvers.values().iterator().next();
			}
		}

		if ( this.resolver == null ) {
			this.resolver = new DefaultBearerTokenResolver();
		}

		exceptionHandling(http)
				.defaultAuthenticationEntryPointFor(
						bearerTokenAuthenticationEntryPoint(),
						(request) -> Optional.ofNullable(request.getHeader("Authorization"))
								.map(authorization -> authorization.startsWith("Bearer "))
								.orElse(false));

		/*
		    TODO: There isn't a shared object for AccessDeniedHandler nor is there the same
		    default/delegate pattern that exceptionHandling supports for entry points. AFAICT,
		    I cannot see whether or not the user has specified an access denied handler,
		    except by way of a @Bean.
		 */

		if (!containsBean(context, AccessDeniedHandler.class)) {
			exceptionHandling(http).accessDeniedHandler(bearerTokenAccessDeniedHandler());
		}

		/*
		   TODO: Not sure how to determine whether or not csrf was specified by the user
		   We have some surrogates like checking for CsrfTokenRepository, but I don't see a way
		   to know, say, that http.csrf() was invoked by the user since this is invoked
		   automatically in getHttp()
		*/


		RequestMatcher requiresCsrf = new AndRequestMatcher(
				CsrfFilter.DEFAULT_CSRF_MATCHER, // somehow get what the user specified
				new NegatedRequestMatcher(new BearerTokenRequestMatcher())
		);

		csrf(http).requireCsrfProtectionMatcher(requiresCsrf);
	}

	@Override
	public void configure(H http) throws Exception {
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);

		http
				.addFilterAfter(oauthResourceAuthenticationFilter(),
						BasicAuthenticationFilter.class);

		if ( !containsBean(context, OAuth2Expressions.class) ) {
			if ( context instanceof ConfigurableApplicationContext ) {
				((ConfigurableApplicationContext) context).getBeanFactory()
						.registerSingleton("oauth2", oauth2());
			}
		}
	}

	private SessionManagementConfigurer<H> sessionManagement(H http) {
		return http.getConfigurer(SessionManagementConfigurer.class);
	}

	private ExceptionHandlingConfigurer<H> exceptionHandling(H http) {
		return http.getConfigurer(ExceptionHandlingConfigurer.class);
	}

	private CsrfConfigurer<H> csrf(H http) {
		return http.getConfigurer(CsrfConfigurer.class);
	}

	private OAuth2Expressions oauth2() {
		return new OAuth2ResourceServerExpressions();
	}

	private BearerTokenAuthenticationFilter oauthResourceAuthenticationFilter() {
		BearerTokenAuthenticationFilter filter =
			new BearerTokenAuthenticationFilter(authenticationManager());

		if ( this.resolver != null ) {
			filter.setBearerTokenResolver(this.resolver);
		}

		return filter;
	}

	private AuthenticationManager authenticationManager() {
		return new ProviderManager(
			Arrays.asList(oauthResourceAuthenticationProvider()));
	}

	private AuthenticationProvider oauthResourceAuthenticationProvider() {
		ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);

		Map<String, JwtDecoder> decoders =
				BeanFactoryUtils.beansOfTypeIncludingAncestors(context, JwtDecoder.class);

		if ( !decoders.isEmpty() &&
				this.jwtAccessTokenFormatConfigurer == null ) {
			JwtDecoder decoder = decoders.values().iterator().next();

			this.jwtAccessTokenFormatConfigurer = new JwtAccessTokenFormatConfigurer(decoder);
		}

		if ( !decoders.isEmpty() &&
				this.jwtAccessTokenFormatConfigurer.jwtDecoder.decoder() == null ) {
			JwtDecoder decoder = decoders.values().iterator().next();

			this.jwtAccessTokenFormatConfigurer.jwtDecoder.decoder(decoder);
		}

		Map<String, KeyProvider> resolvers =
				BeanFactoryUtils.beansOfTypeIncludingAncestors(context, KeyProvider.class);

		if ( !resolvers.isEmpty() &&
				this.jwtAccessTokenFormatConfigurer.jwtDecoder.decoder() == null ) {

			this.jwtAccessTokenFormatConfigurer.jwtDecoder.decoder(
					new NimbusJwtDecoderLocalKeySupport(resolvers.values().iterator().next()));
		}

		if ( this.jwtAccessTokenFormatConfigurer.validators.isEmpty() ) {
			Map<String, JwtTokenValidator> validators =
					BeanFactoryUtils.beansOfTypeIncludingAncestors(context, JwtTokenValidator.class);

			this.jwtAccessTokenFormatConfigurer.validators.addAll(validators.values());
		}

		if ( this.jwtAccessTokenFormatConfigurer.validators.isEmpty() ) {
			this.jwtAccessTokenFormatConfigurer.validators.add(new JwtAccessTokenValidator());
		}

		JwtAccessTokenAuthenticationProvider provider =
			new JwtAccessTokenAuthenticationProvider(
					this.jwtAccessTokenFormatConfigurer.jwtDecoder.decoder(),
					this.jwtAccessTokenFormatConfigurer.validators);

		provider.setAuthoritiesExtractor(this.jwtAccessTokenFormatConfigurer.extractor);

		if ( StringUtils.hasText(this.jwtAccessTokenFormatConfigurer.scopeAttributeName) ) {
			provider.setScopeAttributeName(this.jwtAccessTokenFormatConfigurer.scopeAttributeName);
		}

		return provider;
	}

	private AuthenticationEntryPoint bearerTokenAuthenticationEntryPoint() {
		return new BearerTokenAuthenticationEntryPoint();
	}

	private AccessDeniedHandler bearerTokenAccessDeniedHandler() {
		return new BearerTokenAccessDeniedHandler();
	}

	private boolean containsBean(ApplicationContext context, Class<?> clazz) {
		return !BeanFactoryUtils.beansOfTypeIncludingAncestors(context, clazz).isEmpty();
	}
}
