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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.virgilsecurity.pythia.PythiaContext.Builder;
import com.virgilsecurity.pythia.crypto.PythiaCrypto;
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.Base64;

import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

/**
 * Unit test for {@link PythiaContext}.
 * 
 * @author Andrii Iakovenko
 *
 */
public class PythiaContextTest {

  private String appId;
  private String apiPublicKeyIdentifier;
  private String apiKey;
  private List<String> proofKeys;
  private PythiaCrypto pythiaCrypto;
  private VirgilCrypto crypto;

  /**
   * Setup test.
   * 
   * @throws CryptoException
   *           if something bad happened.
   */
  @Before
  public void setup() throws CryptoException {
    this.pythiaCrypto = new VirgilPythiaCrypto();
    this.crypto = new VirgilCrypto();

    appId = "01234567";
    apiPublicKeyIdentifier = "E224AE66FF1C0E26";
    apiKey = "MC4CAQAwBQYDK2VwBCIEIDmXHZcu0oUcP95mu+CVU3Hw03r6a8Xl1OlTl5YrzJA8";
    proofKeys = Arrays.asList("PK.0.a2V5IDAgZGF0YQ==", "PK.1.a2V5IDEgZGF0YQ==",
        "PK.2.a2V5IDIgZGF0YQ==");
  }

  @Test(expected = IllegalArgumentException.class)
  public void build_noOptions() {
    Builder builder = new Builder();
    builder.build();
  }

  @Test(expected = IllegalArgumentException.class)
  public void build_noAppId() {
    Builder builder = new Builder();
    builder.setApiPublicKeyIdentifier(apiPublicKeyIdentifier).setApiKey(apiKey)
        .setProofKeys(proofKeys).setCrypto(this.crypto).setPythiaCrypto(this.pythiaCrypto).build();
  }

  @Test(expected = IllegalArgumentException.class)
  public void build_noApiPublicKeyIdentifier() {
    Builder builder = new Builder();
    builder.setAppId(appId).setApiKey(apiKey).setProofKeys(proofKeys).setCrypto(this.crypto)
        .setPythiaCrypto(this.pythiaCrypto).build();
  }

  @Test(expected = IllegalArgumentException.class)
  public void build_noApiKey() {
    Builder builder = new Builder();
    builder.setAppId(appId).setApiPublicKeyIdentifier(apiPublicKeyIdentifier)
        .setProofKeys(proofKeys).setCrypto(this.crypto).setPythiaCrypto(this.pythiaCrypto).build();
  }

  @Test(expected = IllegalArgumentException.class)
  public void build_noPythiaCrypto() {
    Builder builder = new Builder();
    builder.setAppId(appId).setApiPublicKeyIdentifier(apiPublicKeyIdentifier).setApiKey(apiKey)
        .setProofKeys(proofKeys).build();
  }

  @Test
  public void build_noVirgilCrypto() {
    Builder builder = new Builder();
    builder.setAppId(appId).setApiPublicKeyIdentifier(apiPublicKeyIdentifier).setApiKey(apiKey)
        .setProofKeys(proofKeys).setPythiaCrypto(this.pythiaCrypto).build();
  }

  @Test
  public void build() {
    Builder builder = new Builder();
    PythiaContext context = builder.setAppId(appId)
        .setApiPublicKeyIdentifier(apiPublicKeyIdentifier).setApiKey(apiKey).setProofKeys(proofKeys)
        .setCrypto(this.crypto).setPythiaCrypto(this.pythiaCrypto).build();

    assertNotNull(context.getAccessTokenProvider());
    assertNotNull(context.getProofKeys());
    assertEquals(2, context.getProofKeys().getCurrentKey().getVersion());
    assertArrayEquals(Base64.decode("a2V5IDIgZGF0YQ=="),
        context.getProofKeys().getCurrentKey().getData());
    assertNotNull(context.getPythiaClient());
    assertNotNull(context.getPythiaCrypto());
  }

}
