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

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * An accessor for projecting scope from an underlying claim set
 *
 * @author Josh Cummings
 * @since 5.1
 */
public interface ScopeClaimAccessor extends ClaimAccessor {

	/**
	 * Coerce a claim into a list of strings, delimiting the string claim by a
	 * {@code delimiter}, if the claim is not already a {@link List}.
	 *
	 * @param claim
	 * @param delimiter
	 * @return
	 */
	default List<String> getClaimAsStringList(String claim, String delimiter) {
		List<String> asList = this.getClaimAsStringList(claim);
		if ( asList != null ) {
			return asList;
		}

		String asString = this.getClaimAsString(claim);
		if ( asString == null ) {
			return null;
		}

		return Arrays.asList(asString.split(delimiter));
	}

	default Collection<String> getScope(String scopeClaimName) {
		return this.getClaimAsStringList(scopeClaimName, " ");
	}
}
