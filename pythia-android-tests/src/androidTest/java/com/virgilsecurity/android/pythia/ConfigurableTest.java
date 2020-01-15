/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.android.pythia;


import androidx.test.platform.app.InstrumentationRegistry;

import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.testcommon.property.EnvPropertyReader;
import com.virgilsecurity.testcommon.utils.PropertyUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Base class for tests which uses environment-specific parameters.
 *
 * @author Andrii Iakovenko
 */
public class ConfigurableTest {

    private static final String ENVIRONMENT_SYS_VAR = "environment";
    private static final String APP_ID = "APP_ID";
    private static final String APP_PRIVATE_KEY = "APP_PRIVATE_KEY";
    private static final String APP_PUBLIC_KEY_ID = "APP_PUBLIC_KEY_ID";
    private static final String PYTHIA_SERVICE_URL = "PYTHIA_SERVICE_URL";

    private final EnvPropertyReader propertyReader;
    private VirgilCrypto crypto;
    private VirgilPrivateKey apiPrivateKey;

    /**
     * Create a new instance of {@link com.virgilsecurity.pythia.ConfigurableTest}.
     */
    public ConfigurableTest() {
        this.crypto = new VirgilCrypto();

        String environment = PropertyUtils.getSystemProperty(ENVIRONMENT_SYS_VAR);

        InputStream resourceEnvStream =
                this.getClass().getClassLoader().getResourceAsStream("testProperties/env.json");
        File tempEnvDirectory = new File(InstrumentationRegistry.getInstrumentation().getTargetContext().getFilesDir(),
                                         "tempEnvDir");
        tempEnvDirectory.mkdirs();

        File tempEnvFile = new File(tempEnvDirectory, "env.json");

        try {
            FileOutputStream outputStream = new FileOutputStream(tempEnvFile);
            byte[] bytes = new byte[resourceEnvStream.available()];
            resourceEnvStream.read(bytes);

            outputStream.write(bytes);
            outputStream.close();
        } catch (Exception exception) {
            throw new RuntimeException();
        }

        if (environment != null)
            propertyReader = new EnvPropertyReader.Builder()
                    .environment(EnvPropertyReader.Environment.fromType(environment))
                    .filePath(tempEnvFile.getParent())
                    .build();
        else
            propertyReader = new EnvPropertyReader.Builder()
                    .filePath(tempEnvFile.getParent())
                    .build();
    }

    /**
     * Get Pythia service base URL.
     *
     * @return Pythia service base URL.
     */
    public String getPythiaServiceUrl() {
        return this.propertyReader.getProperty(PYTHIA_SERVICE_URL);
    }

    /**
     * Get the application identifier.
     *
     * @return the application identifier.
     */
    public String getAppId() {
        return this.propertyReader.getProperty(APP_ID);
    }

    /**
     * Get API Private Key as Base64-encoded string.
     *
     * @return API Private Key as Base64-encoded string.
     */
    public String getApiPrivateKeyStr() {
        return this.propertyReader.getProperty(APP_PRIVATE_KEY);
    }

    /**
     * Get API Private Key.
     *
     * @return API Private Key.
     */
    public VirgilPrivateKey getApiPrivateKey() {
        if (this.apiPrivateKey == null) {
            try {
                this.apiPrivateKey = this.crypto
                        .importPrivateKey(ConvertionUtils.base64ToBytes(getApiPrivateKeyStr())).getPrivateKey();
            } catch (CryptoException e) {
                fail("API Private Key has invalid format");
            }
        }
        return this.apiPrivateKey;
    }

    /**
     * Get API Private Key identifier.
     *
     * @return API Private Key identifier.
     */
    public String getApiPublicKeyId() {
        return this.propertyReader.getProperty(APP_PUBLIC_KEY_ID);
    }

    /**
     * Assert that array is not null and not empty.
     *
     * @param arrayDescription the short array description.
     * @param array            the array to be verified.
     */
    public void assertNotEmpty(String arrayDescription, byte[] array) {
        assertNotNull(String.format("%s should not be null", arrayDescription), array);
        assertTrue(String.format("%s should not be empty", arrayDescription), array.length > 0);
    }

}
