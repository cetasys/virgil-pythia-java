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

package com.virgilsecurity.pythia.client.brainkey;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

import com.virgilsecurity.pythia.ConfigurableTest;
import com.virgilsecurity.pythia.brainkey.BrainKey;
import com.virgilsecurity.pythia.brainkey.BrainKeyContext;
import com.virgilsecurity.pythia.client.PythiaClient;
import com.virgilsecurity.pythia.client.VirgilPythiaClient;
import com.virgilsecurity.pythia.crypto.PythiaCrypto;
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto;
import com.virgilsecurity.pythia.model.exception.VirgilPythiaServiceException;
import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.JwtGenerator;
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.StringUtils;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Test;

/**
 * Integration test for {@link BrainKey}.
 * 
 * @author Andrii Iakovenko
 *
 */
public class BrainKeyTest extends ConfigurableTest {
  private static final String TEXT = "Lorem Ipsum is simply dummy text";

  private VirgilCrypto virgilCrypto;
  private PythiaCrypto pythiaCrypto;
  private PythiaClient pythiaClient;
  private BrainKey brainKey;
  private String identity;

  @Before
  public void setup() {
    this.virgilCrypto = new VirgilCrypto();
    this.pythiaCrypto = new VirgilPythiaCrypto();

    String baseUrl = getPythiaServiceUrl();
    if (StringUtils.isBlank(baseUrl)) {
      this.pythiaClient = new VirgilPythiaClient();
    } else {
      this.pythiaClient = new VirgilPythiaClient(baseUrl);
    }

    this.identity = "pythia_user_" + UUID.randomUUID().toString();
    JwtGenerator generator = new JwtGenerator(getAppId(), getApiPrivateKey(), getApiPublicKeyId(),
        TimeSpan.fromTime(1, TimeUnit.HOURS), new VirgilAccessTokenSigner());
    AccessTokenProvider accessTokenProvider = new GeneratorJwtProvider(generator, identity);

    BrainKeyContext context = new BrainKeyContext.Builder()
        .setAccessTokenProvider(accessTokenProvider).setPythiaCrypto(pythiaCrypto)
        .setPythiaClient(pythiaClient).build();
    this.brainKey = new BrainKey(context);
  }

  @Test
  public void generateKeyPair_noBrainKeyId() throws CryptoException, VirgilPythiaServiceException {
    VirgilKeyPair keyPair = this.brainKey.generateKeyPair("some password");
    assertNotNull(keyPair);

    byte[] data = TEXT.getBytes();
    byte[] encryptedText = this.virgilCrypto.encrypt(data, keyPair.getPublicKey());
    byte[] decryptedText = this.virgilCrypto.decrypt(encryptedText, keyPair.getPrivateKey());

    assertArrayEquals(data, decryptedText);
  }

}
