package wrapProvider;

import static java.io.StreamTokenizer.TT_EOF;
import static java.io.StreamTokenizer.TT_EOL;
import static java.io.StreamTokenizer.TT_WORD;

/*
 * Copyright (c) 2003, 2013, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StreamTokenizer;
import java.io.StringReader;
import java.security.ProviderException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import sun.security.util.PropertyExpander;

/**
 * Configuration container and file parsing.
 *
 * @author Andreas Sterbenz
 * @since 1.5
 */
final class Config {

	// temporary storage for configurations
	private final static Map<String, Config> configMap = new HashMap<String, Config>();

	static Config getConfig(final String name, final InputStream stream) {
		Config config = configMap.get(name);
		if (config != null) {
			return config;
		}
		try {
			config = new Config(name, stream);
			configMap.put(name, config);
			return config;
		} catch (Exception e) {
			throw new ProviderException("Error parsing configuration", e);
		}
	}

	static Config removeConfig(String name) {
		return configMap.remove(name);
	}

	// Reader and StringTokenizer used during parsing
	private Reader reader;

	private StreamTokenizer st;

	private Set<String> parsedKeywords;

	// name suffix of the provider
	private String clientId;

	// name of the clientSecret
	private String clientSecret;

	// vault Uri
	private String vaultUri;

	private Config(String filename, InputStream in) throws IOException {
		if (in == null) {
			if (filename.startsWith("--")) {
				// inline config
				String config = filename.substring(2).replace("\\n", "\n");
				reader = new StringReader(config);
			} else {
				in = new FileInputStream(expand(filename));
			}
		}
		if (reader == null) {
			reader = new BufferedReader(new InputStreamReader(in));
		}
		parsedKeywords = new HashSet<String>();
		st = new StreamTokenizer(reader);
		setupTokenizer();
		parse();
	}

	String getClientId() {
		return clientId;
	}

	String getClientSecret() {
		return clientSecret;
	}

	String getVaultUri() {
		return vaultUri;
	}

	@SuppressWarnings("restriction")
	private static String expand(final String s) throws IOException {
		try {
			return PropertyExpander.expand(s);
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	private void setupTokenizer() {
		st.resetSyntax();
		st.wordChars('a', 'z');
		st.wordChars('A', 'Z');
		st.wordChars('0', '9');
		st.wordChars(':', ':');
		st.wordChars('.', '.');
		st.wordChars('_', '_');
		st.wordChars('-', '-');
		st.wordChars('/', '/');
		st.wordChars('\\', '\\');
		st.wordChars('$', '$');
		st.wordChars('{', '{'); // need {} for property subst
		st.wordChars('}', '}');
		st.wordChars('*', '*');
		st.wordChars('+', '+');
		st.wordChars('~', '~');

		// special: #="(),
		st.whitespaceChars(0, ' ');
		st.commentChar('#');
		st.eolIsSignificant(true);
		st.quoteChar('\"');

	}

	private ConfigurationException excToken(String msg) {
		return new ConfigurationException(msg + " " + st);
	}

	private ConfigurationException excLine(String msg) {
		return new ConfigurationException(msg + ", line " + st.lineno());
	}

	private void parse() throws IOException {
		while (true) {
			int token = nextToken();
			if (token == TT_EOF) {
				break;
			}
			if (token == TT_EOL) {
				continue;
			}
			if (token != TT_WORD) {
				throw excToken("Unexpected token:");
			}
			String word = st.sval;
			if (word.equals("clientId")) {
				clientId = parseLine();
			} else if (word.equals("clientSecret")) {
				clientSecret = parseLine();
			} else if (word.equals("vaultUri")) {
				vaultUri = parseLine();
			} else {
				throw new ConfigurationException("Unknown keyword '" + word + "', line " + st.lineno());
			}
			parsedKeywords.add(word);
		}
		reader.close();
		reader = null;
		st = null;
		parsedKeywords = null;
		if (clientId == null) {
			throw new ConfigurationException("ClientId must be specified");
		}
		if (clientSecret == null) {
			throw new ConfigurationException("Client secret must be specified");
		}
		if (vaultUri == null) {
			throw new ConfigurationException("Vault Uri must be specified");
		}
	}

	//
	// Parsing helper methods
	//
	private int nextToken() throws IOException {
		int token = st.nextToken();
		return token;
	}

	private String parseLine() throws IOException {
		// allow quoted string as part of line
		String s = null;
		while (true) {
			int token = nextToken();
			if ((token == TT_EOL) || (token == TT_EOF)) {
				break;
			}
			if (s == null) {
				s = st.sval;
			} else {
				s = s + " " + st.sval;
			}
		}
		if (s == null) {
			throw excToken("Unexpected empty line");
		}
		return s;
	}

	private void checkDup(String keyword) throws IOException {
		if (parsedKeywords.contains(keyword)) {
			throw excLine(keyword + " must only be specified once");
		}
	}
}

class ConfigurationException extends IOException {
	private static final long serialVersionUID = 254492758807673194L;

	ConfigurationException(String msg) {
		super(msg);
	}
}