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

package cli;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import support.KeyPairs;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;

import static org.springframework.util.ReflectionUtils.findField;
import static org.springframework.util.ReflectionUtils.getField;

public class KeyGen {
	public static class OutputStreamConverter implements IStringConverter<OutputStream> {
		@Override
		public OutputStream convert(String value) {
			try {
				return new FileOutputStream(value);
			} catch ( IOException e ) {
				throw new IllegalArgumentException(e);
			}
		}
	}

	@Parameter(names = "-out", converter = OutputStreamConverter.class)
	OutputStream privateOutput;

	@Parameter(names = "-pubout", converter = OutputStreamConverter.class)
	OutputStream publicOutput;

	public void run() throws Exception {
		if ( this.privateOutput == null ) {
			this.privateOutput = new FileOutputStream("id_rsa");
		}

		if ( this.publicOutput == null ) {
			if ( this.privateOutput instanceof FileOutputStream ) {
				Field f = findField(FileOutputStream.class, "path");
				f.setAccessible(true);
				String path = (String) getField(f, this.privateOutput);
				this.publicOutput = new FileOutputStream(path + ".pub");
			} else {
				throw new IllegalArgumentException("-pubout wasn't specified and couldn't be defaulted based on -out");
			}
		}

		KeyPairs.rsa256()
				.x509(this.publicOutput)
				.pkcs8(this.privateOutput);
	}

	public static void main(String[] args) throws Exception {
		KeyGen keyGen = new KeyGen();
		JCommander.newBuilder()
				.addObject(keyGen)
				.build()
				.parse(args);

		keyGen.run();
	}
}
