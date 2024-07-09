/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.sasl.gssapi;

import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.jboss.logging.Logger;

/**
 * Utility class for the JAAS based logins.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class JaasUtil {

    private static Logger log = Logger.getLogger(JaasUtil.class);

    private static final boolean IS_IBM = System.getProperty("java.vendor").contains("IBM");

    public static Subject loginClient() throws LoginException {
        log.debug("loginClient");
        return login("jduke", "theduke".toCharArray(), false, null);
    }

    public static Subject loginServer(String keyTabFile) throws LoginException {
        log.debug("loginServer");
        return login("sasl/test_server_1", "servicepwd".toCharArray(), true, keyTabFile);
    }

    static Subject login(final String userName, final char[] password, final boolean server, final String keyTabFile) throws LoginException {
        Subject theSubject = new Subject();
        CallbackHandler cbh = new UsernamePasswordCBH(userName, password);
        Configuration config;
        if (server) {
            config = createGssProxyConfiguration(userName, keyTabFile);
        } else {
            config = createJaasConfiguration(false);
        }
        LoginContext lc = new LoginContext("KDC", theSubject, cbh, config);
        lc.login();

        /*
        This seems to be the main issue for:
            GssapiCompatibilitySuiteChild.test1Auth
            GssapiCompatibilitySuiteChild.test2AuthInt
            GssapiCompatibilitySuiteChild.test3AuthConf
        to fail.
        When debugging the login() method above. Lots of test pass by here and just work, but these 3 tests have
        something characteristic to them which explains the KrbException we're seeing:
            Caused by: KrbException: Request is a replay (34) - Request is a replay

        This means that the ticket is older than 5 minutes. This was introduced to avoid replay attacks.
        After running mvn clean test -Dtest=GssApiTestSuite and you look at target/surefire-reports/org.wildfly.security.sasl.gssapi.GssapiTestSuite-output.txt
        this seems to be the reason:
            01:00:00,123 DEBUG (main) [org.wildfly.security.sasl.gssapi.JaasUtil] <JaasUtil.java:89> Login private credentials: [Ticket (hex) =
            0000: 61 81 FB 30 81 F8 A0 03   02 01 05 A1 0D 1B 0B 57  a..0...........W
            0010: 49 4C 44 46 4C 59 2E 4F   52 47 A2 20 30 1E A0 03  ILDFLY.ORG. 0...
            0020: 02 01 02 A1 17 30 15 1B   06 6B 72 62 74 67 74 1B  .....0...krbtgt.
            0030: 0B 57 49 4C 44 46 4C 59   2E 4F 52 47 A3 81 BF 30  .WILDFLY.ORG...0
            0040: 81 BC A0 03 02 01 11 A2   81 B4 04 81 B1 37 BA F0  .............7..
            0050: 64 53 81 BF EC 6E 3B 3B   71 14 31 9A FA F9 B5 5B  dS...n;;q.1....[
            0060: 72 1E 80 81 56 1B 25 DB   A2 A2 A5 46 D3 E3 35 68  r...V.%....F..5h
            0070: 47 D4 61 BC 3A C3 77 35   BF 52 49 A0 5C FE EC 4A  G.a.:.w5.RI.\..J
            0080: 05 ED 58 BA A3 1B 1C 0B   61 CA 60 A3 68 7D CA E8  ..X.....a.`.h...
            0090: D6 D4 7D 2D 27 92 3E 2E   35 9A 7A 3B 82 78 31 72  ...-'.>.5.z;.x1r
            00A0: 79 51 E2 88 09 E7 70 AF   30 E4 21 36 CF 65 5E 9D  yQ....p.0.!6.e^.
            00B0: FA 78 D1 6B C4 C9 38 93   74 B5 3B EB E1 C8 4B 8C  .x.k..8.t.;...K.
            00C0: 37 F2 F7 F1 C2 E2 E5 EE   99 D5 E0 E4 AC 2A 89 88  7............*..
            00D0: C5 06 8A B9 CD 3A F0 D9   24 4D 74 7F 7E 3C 0B 0E  .....:..$Mt..<..
            00E0: 77 10 0B 16 F6 B3 A4 14   1F 26 1B FF 77 4F 80 5E  w........&..wO.^
            00F0: A7 CD DB E9 4B 20 2E 82   33 51 00 F9 88 EA        ....K ..3Q....

            Client Principal = jduke@WILDFLY.ORG
            Server Principal = krbtgt/WILDFLY.ORG@WILDFLY.ORG
            Session Key = EncryptionKey: keyType=17 keyBytes (hex dump)=
            0000: 6C 75 84 77 C0 5F 5A A5   6C 01 3F 0A 30 0F 18 DB  lu.w._Z.l.?.0...


            Forwardable Ticket true
            Forwarded Ticket false
            Proxiable Ticket false
            Proxy Ticket false
            Postdated Ticket false
            Renewable Ticket false
            Initial Ticket false
            Auth Time = Thu Jan 01 01:00:00 GMT 1970 <===== Authentication time in 1970! btw this is UNIX epoch 3600
            Start Time = Thu Jan 01 01:00:00 GMT 1970
            End Time = Fri Jan 02 01:00:00 GMT 1970
            Renew Till = null
            Client Addresses  Null , Kerberos Principal jduke@WILDFLY.ORGKey Version 0key EncryptionKey: keyType=17 keyBytes (hex dump)=
            0000: 7F 17 9E 14 AB B6 F9 A5   6C 1F C8 71 F5 07 A1 A6  ........l..q....

            ]


         This ticket only happens when going through those 3 tests. I have no idea what is going on but that's the only
         reason I could find so far.
         */
        log.debug("Login public credentials: " + lc.getSubject().getPublicCredentials());
        log.debug("Login private credentials: " + lc.getSubject().getPrivateCredentials());

        return theSubject;
    }

    private static Configuration createJaasConfiguration(final boolean server) {
        return new Configuration() {

            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                if ("KDC".equals(name) == false) {
                    throw new IllegalArgumentException(String.format("Unexpected name '%s'", name));
                }

                AppConfigurationEntry[] entries = new AppConfigurationEntry[1];
                Map<String, Object> options = new HashMap<String, Object>();
                options.put("debug", "true");
                options.put("refreshKrb5Config", "true");

                if (IS_IBM) {
                    options.put("noAddress", "true");
                    options.put("credsType", server ? "acceptor" : "initiator");
                    entries[0] = new AppConfigurationEntry("com.ibm.security.auth.module.Krb5LoginModule", REQUIRED, options);
                } else {
                    options.put("storeKey", "true");
                    options.put("isInitiator", server ? "false" : "true");
                    entries[0] = new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule", REQUIRED, options);
                }

                return entries;
            }

        };
    }

    private static Configuration createGssProxyConfiguration(final String principal, final String keyTabFile) {
        return new Configuration() {

            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                if ("KDC".equals(name) == false) {
                    throw new IllegalArgumentException(String.format("Unexpected name '%s'", name));
                }

                AppConfigurationEntry[] entries = new AppConfigurationEntry[1];
                Map<String, Object> options = new HashMap<String, Object>();
                options.put("debug", "true");
                options.put("refreshKrb5Config", "true");
                options.put("principal", principal);

                if (IS_IBM) {
                    options.put("useKeytab", keyTabFile);
                    options.put("noAddress", "true");
                    options.put("credsType", "acceptor");
                    entries[0] = new AppConfigurationEntry("com.ibm.security.auth.module.Krb5LoginModule", REQUIRED, options);
                } else {
                    options.put("useKeyTab", "true");
                    options.put("keyTab", keyTabFile);
                    options.put("doNotPrompt", "true");
                    options.put("storeKey", "true");
                    options.put("isInitiator", "false");
                    entries[0] = new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule", REQUIRED, options);
                }

                return entries;
            }

        };
    }

    private static class UsernamePasswordCBH implements CallbackHandler {

        /*
         * Note: We use CallbackHandler implementations like this in test cases as test cases need to run unattended, a true
         * CallbackHandler implementation should interact directly with the current user to prompt for the username and
         * password.
         *
         * i.e. In a client app NEVER prompt for these values in advance and provide them to a CallbackHandler like this.
         */

        private final String username;
        private final char[] password;

        private UsernamePasswordCBH(final String username, final char[] password) {
            this.username = username;
            this.password = password;
        }

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback current : callbacks) {
                if (current instanceof NameCallback) {
                    NameCallback ncb = (NameCallback) current;
                    ncb.setName(username);
                } else if (current instanceof PasswordCallback) {
                    PasswordCallback pcb = (PasswordCallback) current;
                    pcb.setPassword(password);
                } else {
                    throw new UnsupportedCallbackException(current);
                }
            }

        }

    }

}
