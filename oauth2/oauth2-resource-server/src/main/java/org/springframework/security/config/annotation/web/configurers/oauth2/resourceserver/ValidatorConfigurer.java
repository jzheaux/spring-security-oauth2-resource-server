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

import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.resourceserver.authentication.AudienceValidator;
import org.springframework.security.oauth2.resourceserver.authentication.JwtAccessTokenValidator;
import org.springframework.security.oauth2.resourceserver.authentication.JwtClaimValidator;

import java.time.Duration;

public final class ValidatorConfigurer {

	public static TimestampValidatorConfigurer timestamps() {
		return new TimestampValidatorConfigurer();
	}

	public static class TimestampValidatorConfigurer {
		public TimestampValidatorDurationConfigurer areValidWithin(long time) {
			return new TimestampValidatorDurationConfigurer(time);
		}
	}

	public static class TimestampValidatorDurationConfigurer {
		private long time;

		public TimestampValidatorDurationConfigurer(long time) {
			this.time = time;
		}

		public JwtAccessTokenValidator seconds() {
			return new JwtAccessTokenValidator(Duration.ofSeconds(this.time));
		}

		public JwtAccessTokenValidator minutes() {
			return new JwtAccessTokenValidator(Duration.ofMinutes(this.time));
		}
	}

	public static AudienceValidatorConfigurer audience() {
		return new AudienceValidatorConfigurer();
	}

	public static class AudienceValidatorConfigurer {
		public AudienceValidator isOneOf(String... audience) {
			return new AudienceValidator(audience);
		}
	}

	public static ClaimValidatorConfigurer claim(String name) {
		return new ClaimValidatorConfigurer(name);
	}

	public static ClaimValidatorConfigurer issuer() {
		return new ClaimValidatorConfigurer(JwtClaimNames.ISS);
	}

	public static class ClaimValidatorConfigurer {
		private String name;

		public ClaimValidatorConfigurer(String name) {
			this.name = name;
		}

		public JwtClaimValidator is(String issuers) {
			return new JwtClaimValidator(this.name, issuers);
		}
	}
}
