/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
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

package com.virgilsecurity.pythia;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;

import java.util.Arrays;
import java.util.List;

/**
 * Base class for tests which uses environment-specific parameters.
 * 
 * @author Andrii Iakovenko
 *
 */
public class ConfigurableTest {

  private VirgilCrypto crypto;
  private String accountId;
  private String appId;
  private String apiPrivateKeyStr;
  private VirgilPrivateKey apiPrivateKey;
  private VirgilPublicKey apiPublicKey;
  private String apiPublicKeyId;
  private String proofKeys1;
  private String proofKeys2;
  private String proofKeys3;
  private String updateToken2to3;

  /**
   * Create a new instance of {@link ConfigurableTest}.
   *
   */
  public ConfigurableTest() {
    this.crypto = new VirgilCrypto();
  }

  /**
   * Get Pythia service base URL.
   * 
   * @return Pythia service base URL.
   */
  public String getPythiaServiceUrl() {
    return getPropertyByName("PYTHIA_SERVICE_URL");
  }

  /**
   * Get the account identifier.
   * 
   * @return the account identifier.
   */
  public String getAccountId() {
    if (this.accountId == null) {
      this.accountId = getPropertyByName("ACCOUNT_ID");
      if (this.accountId == null) {
        fail("Account ID is not defined");
      }
    }
    return this.accountId;
  }

  /**
   * Get the application identifier.
   * 
   * @return the application identifier.
   */
  public String getAppId() {
    if (this.appId == null) {
      this.appId = getPropertyByName("APP_ID");
      if (this.appId == null) {
        fail("App ID is not defined");
      }
    }
    return this.appId;
  }

  /**
   * Get API Private Key as Base64-encoded string.
   * 
   * @return API Private Key as Base64-encoded string.
   */
  public String getApiPrivateKeyStr() {
    if (this.apiPrivateKeyStr == null) {
      this.apiPrivateKeyStr = getPropertyByName("API_PRIVATE_KEY");
      if (this.apiPrivateKeyStr == null) {
        fail("API Private Key is not defined");
      }
    }
    return this.apiPrivateKeyStr;
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
            .importPrivateKey(ConvertionUtils.base64ToBytes(getApiPrivateKeyStr()));
      } catch (CryptoException e) {
        fail("API Private Key has invalid format");
      }
    }
    return this.apiPrivateKey;
  }

  /**
   * Get API Public Key.
   * 
   * @return API Public Key.
   */
  public VirgilPublicKey getApiPublicKey() {
    if (this.apiPublicKey == null) {
      try {
        this.apiPublicKey = this.crypto
            .importPublicKey(ConvertionUtils.base64ToBytes(getPropertyByName("API_PUBLIC_KEY")));
      } catch (CryptoException e) {
        fail("API Public Key is not defined");
      }
    }
    return this.apiPublicKey;
  }

  /**
   * Get API Private Key identifier.
   * 
   * @return API Private Key identifier.
   */
  public String getApiPublicKeyId() {
    if (this.apiPublicKeyId == null) {
      this.apiPublicKeyId = getPropertyByName("API_PUBLIC_KEY_ID");
      if (this.apiPublicKeyId == null) {
        fail("API Public Key ID is not defined");
      }
    }
    return this.apiPublicKeyId;
  }

  /**
   * Get the single proof key.
   * 
   * @return the proof key.
   */
  public List<String> getProofKeys1() {
    if (this.proofKeys1 == null) {
      this.proofKeys1 = getPropertyByName("PROOF_KEYS1");
      if (this.proofKeys1 == null) {
        fail("PROOF_KEYS1 is not defined");
      }
    }
    return Arrays.asList(this.proofKeys1);
  }

  /**
   * Get the proof keys pair.
   * 
   * @return the proof keys.
   */
  public List<String> getProofKeys2() {
    if (this.proofKeys2 == null) {
      this.proofKeys2 = getPropertyByName("PROOF_KEYS2");
      if (this.proofKeys2 == null) {
        fail("PROOF_KEYS2 is not defined");
      }
    }
    return Arrays.asList(this.proofKeys2.split(","));
  }

  /**
   * Get the proof keys trinity.
   * 
   * @return the proof keys.
   */
  public List<String> getProofKeys3() {
    if (this.proofKeys3 == null) {
      this.proofKeys3 = getPropertyByName("PROOF_KEYS3");
      if (this.proofKeys3 == null) {
        fail("PROOF_KEYS3 is not defined");
      }
    }
    return Arrays.asList(this.proofKeys3.split(","));
  }

  /**
   * Get update token from version 2 to version3.
   * 
   * @return the update token.
   */
  public String getUpdateToken2to3() {
    if (this.updateToken2to3 == null) {
      this.updateToken2to3 = getPropertyByName("UPDATE_TOKEN_2_3");
      if (this.updateToken2to3 == null) {
        fail("UPDATE_TOKEN_2_3 is not defined");
      }
    }
    return this.updateToken2to3;
  }

  /**
   * Get property value by property name.
   * 
   * @param propertyName
   *          the property name.
   * @return the property value of {@code null} if property is not set.
   */
  public String getPropertyByName(String propertyName) {
    String result = System.getProperty(propertyName);
    if (StringUtils.isBlank(result)) {
      result = System.getenv(propertyName);
    }
    if (StringUtils.isBlank(result)) {
      return null;
    }
    return result;
  }

  /**
   * Assert that array is not null and not empty.
   * 
   * @param arrayDescription
   *          the short array description.
   * @param array
   *          the array to be verified.
   */
  public void assertNotEmpty(String arrayDescription, byte[] array) {
    assertNotNull(String.format("%s should not be null", arrayDescription), array);
    assertTrue(String.format("%s should not be empty", arrayDescription), array.length > 0);
  }

}
