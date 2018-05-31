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

package com.virgilsecurity.pythia.brainkey;

import com.virgilsecurity.pythia.client.PythiaClient;
import com.virgilsecurity.pythia.crypto.PythiaCrypto;
import com.virgilsecurity.sdk.crypto.KeysType;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;

/**
 * This class stores BrainKey configuration.
 * 
 * @author Andrii Iakovenko
 *
 */
public class BrainKeyContext {

  private PythiaClient pythiaClient;

  private PythiaCrypto pythiaCrypto;

  private AccessTokenProvider accessTokenProvider;

  private KeysType keyPairType;

  /**
   * Create a new instance of {@link BrainKeyContext}.
   *
   * @param pythiaCrypto
   *          the Pythia Crypto.
   * @param pythiaClient
   *          the Pythia client.
   * @param accessTokenProvider
   *          the access token provider.
   * @param keyPairType
   *          the key type.
   */
  private BrainKeyContext(PythiaCrypto pythiaCrypto, PythiaClient pythiaClient,
      AccessTokenProvider accessTokenProvider, KeysType keyPairType) {
    super();
    this.pythiaClient = pythiaClient;
    this.pythiaCrypto = pythiaCrypto;
    this.accessTokenProvider = accessTokenProvider;
    this.keyPairType = keyPairType;
  }

  /**
   * Builder for {@link BrainKeyContext}.
   * 
   * @author Andrii Iakovenko
   *
   */
  public static class Builder {
    private PythiaCrypto pythiaCrypto;
    private PythiaClient pythiaClient;
    private AccessTokenProvider accessTokenProvider;
    private KeysType keyPairType;

    /**
     * Create a new instance of {@link BrainKeyContext.Builder}.
     *
     */
    public Builder() {
      keyPairType = KeysType.FAST_EC_ED25519;
    }

    /**
     * Build {@linkplain BrainKeyContext}.
     * 
     * @return the built {@linkplain BrainKeyContext}.
     */
    public BrainKeyContext build() {
      if (pythiaClient == null) {
        throw new IllegalArgumentException("Pythia client should be set");
      }

      if (pythiaCrypto == null) {
        throw new IllegalArgumentException("Pythia Crypto should be set");
      }

      if (accessTokenProvider == null) {
        throw new IllegalArgumentException("Access token provider should be set");
      }

      if (keyPairType == null) {
        throw new IllegalArgumentException("Default key type should be set");
      }

      return new BrainKeyContext(pythiaCrypto, pythiaClient, accessTokenProvider, keyPairType);
    }

    /**
     * Set Pythia Crypto.
     * 
     * @param pythiaCrypto
     *          the Pythia Crypto to set.
     * @return this builder instance.
     */
    public Builder setPythiaCrypto(PythiaCrypto pythiaCrypto) {
      this.pythiaCrypto = pythiaCrypto;
      return this;
    }

    /**
     * Set Pythia client.
     * 
     * @param pythiaClient
     *          the Pythia client to set.
     * @return this builder instance.
     */
    public Builder setPythiaClient(PythiaClient pythiaClient) {
      this.pythiaClient = pythiaClient;
      return this;

    }

    /**
     * Set access token provider.
     * 
     * @param accessTokenProvider
     *          the access token provider to set.
     * @return this builder instance.
     */
    public Builder setAccessTokenProvider(AccessTokenProvider accessTokenProvider) {
      this.accessTokenProvider = accessTokenProvider;
      return this;
    }

    /**
     * Set key type.
     * 
     * @param keyPairType
     *          the key type to set
     * @return this builder instance.
     */
    public Builder setKeyPairType(KeysType keyPairType) {
      this.keyPairType = keyPairType;
      return this;
    }

  }

  /**
   * Get Pythia client.
   * 
   * @return the pythiaClient
   */
  public PythiaClient getPythiaClient() {
    return pythiaClient;
  }

  /**
   * Get Pythia Crypto.
   * 
   * @return the pythiaCrypto
   */
  public PythiaCrypto getPythiaCrypto() {
    return pythiaCrypto;
  }

  /**
   * Get access token provider.
   * 
   * @return the accessTokenProvider
   */
  public AccessTokenProvider getAccessTokenProvider() {
    return accessTokenProvider;
  }

  /**
   * Get key type.
   * 
   * @return the keyPairType
   */
  public KeysType getKeyPairType() {
    return keyPairType;
  }

}
