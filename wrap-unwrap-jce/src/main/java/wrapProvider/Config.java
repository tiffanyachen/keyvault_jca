package wrapProvider;

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

import java.io.*;
import static java.io.StreamTokenizer.*;
import java.math.BigInteger;
import java.util.*;

import java.security.*;

import sun.security.action.GetPropertyAction;
import sun.security.util.PropertyExpander;

import sun.security.pkcs11.wrapper.*;
import static sun.security.pkcs11.wrapper.PKCS11Constants.*;
import static sun.security.pkcs11.wrapper.CK_ATTRIBUTE.*;


/**
 * Configuration container and file parsing.
 *
 * @author  Andreas Sterbenz
 * @since   1.5
 */
final class Config {

    static final int ERR_HALT       = 1;
    static final int ERR_IGNORE_ALL = 2;
    static final int ERR_IGNORE_LIB = 3;

    // same as allowSingleThreadedModules but controlled via a system property
    // and applied to all providers. if set to false, no SunPKCS11 instances
    // will accept single threaded modules regardless of the setting in their
    // config files.
    private static final boolean staticAllowSingleThreadedModules;

    static {
        String p = "sun.security.pkcs11.allowSingleThreadedModules";
        String s = AccessController.doPrivileged(new GetPropertyAction(p));
        if ("false".equalsIgnoreCase(s)) {
            staticAllowSingleThreadedModules = false;
        } else {
            staticAllowSingleThreadedModules = true;
        }
    }

    // temporary storage for configurations
    // needed because the SunPKCS11 needs to call the superclass constructor
    // in provider before accessing any instance variables
    private final static Map<String,Config> configMap =
                                        new HashMap<String,Config>();

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

    private final static boolean DEBUG = false;

    private static void debug(Object o) {
        if (DEBUG) {
            System.out.println(o);
        }
    }

    // Reader and StringTokenizer used during parsing
    private Reader reader;

    private StreamTokenizer st;

    private Set<String> parsedKeywords;

    // name suffix of the provider
    private String clientId;

    // name of the clientSecret
    private String clientSecret;
    
    //vault Uri
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
        // XXX check ASCII table and add all other characters except special

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
                clientId = parseStringEntry(word);
            } else if (word.equals("clientSecret")) {
            	clientSecret = parseLine();
            } else if (word.equals("vaultUri")) {
            	vaultUri = parseStringEntry(word);
            } else {
                throw new ConfigurationException
                        ("Unknown keyword '" + word + "', line " + st.lineno());
            }
            parsedKeywords.add(word);
        }
        reader.close();
        reader = null;
        st = null;
        parsedKeywords = null;
        if (clientId == null) {
            throw new ConfigurationException("name must be specified");
        }
    }

    //
    // Parsing helper methods
    //

    private int nextToken() throws IOException {
        int token = st.nextToken();
        debug(st);
        return token;
    }

    private void parseEquals() throws IOException {
        int token = nextToken();
        if (token != '=') {
            throw excToken("Expected '=', read");
        }
    }

    private void parseOpenBraces() throws IOException {
        while (true) {
            int token = nextToken();
            if (token == TT_EOL) {
                continue;
            }
            if ((token == TT_WORD) && st.sval.equals("{")) {
                return;
            }
            throw excToken("Expected '{', read");
        }
    }

    private boolean isCloseBraces(int token) {
        return (token == TT_WORD) && st.sval.equals("}");
    }

    private String parseWord() throws IOException {
        int token = nextToken();
        if (token != TT_WORD) {
            throw excToken("Unexpected value:");
        }
        return st.sval;
    }

    private String parseStringEntry(String keyword) throws IOException {
        checkDup(keyword);
        parseEquals();

        int token = nextToken();
        if (token != TT_WORD && token != '\"') {
            // not a word token nor a string enclosed by double quotes
            throw excToken("Unexpected value:");
        }
        String value = st.sval;

        debug(keyword + ": " + value);
        return value;
    }


    private String parseLine() throws IOException {
        // allow quoted string as part of line
        String s = null;
        while (true) {
            int token = nextToken();
            if ((token == TT_EOL) || (token == TT_EOF)) {
                break;
            }
//            if (token != TT_WORD && token != '\"') {
//                throw excToken("Unexpected value");
//            }
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

    private int decodeNumber(String str) throws IOException {
        try {
            if (str.startsWith("0x") || str.startsWith("0X")) {
                return Integer.parseInt(str.substring(2), 16);
            } else {
                return Integer.parseInt(str);
            }
        } catch (NumberFormatException e) {
            throw excToken("Expected number, read");
        }
    }

    private static boolean isNumber(String s) {
        if (s.length() == 0) {
            return false;
        }
        char ch = s.charAt(0);
        return ((ch >= '0') && (ch <= '9'));
    }


    private static boolean isByteArray(String val) {
        return val.startsWith("0h");
    }

    private byte[] decodeByteArray(String str) throws IOException {
        if (str.startsWith("0h") == false) {
            throw excToken("Expected byte array value, read");
        }
        str = str.substring(2);
        // XXX proper hex parsing
        try {
            return new BigInteger(str, 16).toByteArray();
        } catch (NumberFormatException e) {
            throw excToken("Expected byte array value, read");
        }
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