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

import com.virgilsecurity.pythia.client.PythiaClient;
import com.virgilsecurity.pythia.client.VirgilPythiaClient;
import com.virgilsecurity.pythia.crypto.PythiaCrypto;
import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.Jwt;
import com.virgilsecurity.sdk.jwt.JwtGenerator;
import com.virgilsecurity.sdk.jwt.TokenContext;
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider;
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider.RenewJwtCallback;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.Base64;
import com.virgilsecurity.sdk.utils.StringUtils;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Pythia-related config.
 * 
 * @author Andrii Iakovenko
 *
 */
public class PythiaContext {

  private static final Logger LOGGER = Logger.getLogger(PythiaContext.class.getName());

  private ProofKeys proofKeys;
  private AccessTokenProvider accessTokenProvider;
  private PythiaClient pythiaClient;
  private PythiaCrypto pythiaCrypto;

  private PythiaContext(ProofKeys proofKeys, PythiaCrypto pythiaCrypto, PythiaClient client,
      AccessTokenProvider accessTokenProvider) {
    this.proofKeys = proofKeys;
    this.pythiaCrypto = pythiaCrypto;
    this.pythiaClient = client;
    this.accessTokenProvider = accessTokenProvider;
  }

  /**
   * Get proof keys.
   * 
   * @return the proof keys.
   */
  public ProofKeys getProofKeys() {
    return proofKeys;
  }

  /**
   * Get the access token provider.
   * 
   * @return the access token provider.
   */
  public AccessTokenProvider getAccessTokenProvider() {
    return accessTokenProvider;
  }

  /**
   * Get the {@link PythiaClient}.
   * 
   * @return the Pythia client.
   */
  public PythiaClient getPythiaClient() {
    return pythiaClient;
  }

  /**
   * Get the {@link PythiaCrypto}.
   * 
   * @return the Pythia Crypto.
   */
  public PythiaCrypto getPythiaCrypto() {
    return pythiaCrypto;
  }

  /**
   * The builder for {@link PythiaContext}.
   * 
   * @author Andrii Iakovenko
   *
   */
  public static class Builder {
    private String apiKey;
    private String apiPublicKeyIdentifier;
    private String appId;
    private List<String> proofKeys;
    private VirgilCrypto crypto;
    private PythiaCrypto pythiaCrypto;
    private String pythiaServiceUrl;

    /**
     * Build the Pythia-related config.
     * 
     * @return the instance of Pythia-related config.
     */
    public PythiaContext build() {
      if (StringUtils.isBlank(this.appId)) {
        LOGGER.severe("Application identifier should be set");
        throw new IllegalArgumentException("Application identifier should be set");
      }
      if (StringUtils.isBlank(this.apiPublicKeyIdentifier)) {
        LOGGER.severe("API public key identifier should be set");
        throw new IllegalArgumentException("API public key identifier should be set");
      }
      if (StringUtils.isBlank(this.apiKey)) {
        LOGGER.severe("API key should be set");
        throw new IllegalArgumentException("API key should be set");
      }
      if (this.pythiaCrypto == null) {
        LOGGER.severe("Pythia Crypto should be set");
        throw new IllegalArgumentException("Pythia Crypto should be set");
      }

      if (this.crypto == null) {
        this.crypto = new VirgilCrypto();
      }
      VirgilCrypto crypto = this.crypto;

      VirgilPrivateKey apiPrivateKey = null;
      try {
        byte[] apiKeyData = Base64.decode(this.apiKey);
        apiPrivateKey = crypto.importPrivateKey(apiKeyData);
      } catch (Exception e) {
        throw new IllegalArgumentException("API key has invalid format", e);
      }

      final JwtGenerator generator = new JwtGenerator(this.appId, apiPrivateKey,
          this.apiPublicKeyIdentifier, TimeSpan.fromTime(1, TimeUnit.HOURS),
          new VirgilAccessTokenSigner(this.crypto));

      RenewJwtCallback renewJwtCallback = new RenewJwtCallback() {

        @Override
        public Jwt renewJwt(TokenContext tokenContext) {
          try {
            return generator.generateToken("PYTHIA-CLIENT");
          } catch (CryptoException e) {
            // This should never happen
            LOGGER.log(Level.SEVERE, "Jwt token couldn't be generated", e);
          }
          return null;
        }
      };
      AccessTokenProvider accessTokenProvider = new CachingJwtProvider(renewJwtCallback);
      ProofKeys proofKeys = new ProofKeys(this.proofKeys);
      PythiaClient client;
      if (this.pythiaServiceUrl == null) {
        client = new VirgilPythiaClient();
      } else {
        client = new VirgilPythiaClient(this.pythiaServiceUrl);
      }

      return new PythiaContext(proofKeys, pythiaCrypto, client, accessTokenProvider);
    }

    /**
     * Set API key.
     * 
     * @param apiKey
     *          Base64-encoded API key.
     * @return {@link Builder} instance.
     */
    public Builder setApiKey(String apiKey) {
      this.apiKey = apiKey;
      return this;
    }

    /**
     * Set API public key identifier.
     * 
     * @param apiPublicKeyIdentifier
     *          the API public key identifier to set.
     * @return {@link Builder} instance.
     */
    public Builder setApiPublicKeyIdentifier(String apiPublicKeyIdentifier) {
      this.apiPublicKeyIdentifier = apiPublicKeyIdentifier;
      return this;
    }

    /**
     * Set Virgil Application identifier.
     * 
     * @param appId
     *          the application identifier to set.
     * @return {@link Builder} instance.
     */
    public Builder setAppId(String appId) {
      this.appId = appId;
      return this;
    }

    /**
     * Set Pythia public keys.
     * 
     * @param proofKeys
     *          the proofKeys to set
     * @return {@link Builder} instance.
     */
    public Builder setProofKeys(List<String> proofKeys) {
      this.proofKeys = proofKeys;
      return this;
    }

    /**
     * Set Pythia Crypto.
     * 
     * @param pythiaCrypto
     *          the Pythia Crypto to set
     * @return {@link Builder} instance.
     */
    public Builder setPythiaCrypto(PythiaCrypto pythiaCrypto) {
      this.pythiaCrypto = pythiaCrypto;
      return this;
    }

    /**
     * Set Virgil Crypto.
     * 
     * @param crypto
     *          the Virgil Crypto to set.
     * @return {@link Builder} instance.
     */
    public Builder setCrypto(VirgilCrypto crypto) {
      this.crypto = crypto;
      return this;
    }

    /**
     * Set Pythia service base URL.
     * 
     * @param pythiaServiceUrl
     *          the Pythia service base URL.
     * @return {@link Builder} instance.
     */
    public Builder setPythiaServiceUrl(String pythiaServiceUrl) {
      this.pythiaServiceUrl = pythiaServiceUrl;
      return this;
    }

  }

}
