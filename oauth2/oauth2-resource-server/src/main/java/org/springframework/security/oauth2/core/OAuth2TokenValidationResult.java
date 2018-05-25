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

package org.springframework.security.oauth2.core;

import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

public final class OAuth2TokenValidationResult {
	public static final OAuth2TokenValidationResult SUCCESS =
			new OAuth2TokenValidationResult();

	private final Collection<Detail> details;

	public OAuth2TokenValidationResult() {
		this(Collections.emptyList());
	}

	public OAuth2TokenValidationResult(Collection<Detail> details) {
		Assert.notNull(details, "details must not be null");
		this.details = Collections.unmodifiableCollection(details);
	}

	public static OAuth2TokenValidationResult error(String reason, Object... params) {
		return new OAuth2TokenValidationResult.Builder()
				.error(reason, params).build();
	}

	public boolean isSuccess() {
		return this.details.stream().noneMatch(Detail::isFailure);
	}

	public String getFailureReasons() {
		return this.details.stream()
					.filter(Detail::isFailure)
					.map(Detail::getReason)
					.collect(Collectors.joining(" - "));
	}


	public static class Builder {
		private final Collection<Detail> details = new ArrayList<>();

		public Builder error(String reason, Object... params) {
			String message = String.format(reason, params);
			this.details.add(new Detail(false, message));
			return this;
		}

		public Builder success(String reason, Object... params) {
			String message = String.format(reason, params);
			this.details.add(new Detail(true, message));
			return this;
		}

		public Builder append(OAuth2TokenValidationResult result) {
			this.details.addAll(result.details);
			return this;
		}

		public OAuth2TokenValidationResult build() {
			return new OAuth2TokenValidationResult(this.details);
		}


	}

	public static class Detail {
		final boolean success;
		final String reason;

		public Detail(boolean success, String reason) {
			this.success = success;
			this.reason = reason;
		}

		public boolean isFailure() {
			return !this.success;
		}

		public String getReason() {
			return this.reason;
		}
	}
}
