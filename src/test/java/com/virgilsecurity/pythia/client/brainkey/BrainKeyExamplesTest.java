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

import static org.junit.Assert.assertNotNull;

import com.virgilsecurity.pythia.ConfigurableTest;
import com.virgilsecurity.pythia.brainkey.BrainKey;
import com.virgilsecurity.pythia.brainkey.BrainKeyContext;
import com.virgilsecurity.pythia.client.PythiaClient;
import com.virgilsecurity.pythia.client.VirgilPythiaClient;
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto;
import com.virgilsecurity.pythia.model.exception.VirgilPythiaServiceException;
import com.virgilsecurity.sdk.cards.Card;
import com.virgilsecurity.sdk.cards.CardManager;
import com.virgilsecurity.sdk.cards.validation.CardVerifier;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.CardCrypto;
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner;
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.Jwt;
import com.virgilsecurity.sdk.jwt.JwtGenerator;
import com.virgilsecurity.sdk.jwt.TokenContext;
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider;
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider.RenewJwtCallback;
import com.virgilsecurity.sdk.jwt.accessProviders.CallbackJwtProvider;
import com.virgilsecurity.sdk.jwt.accessProviders.CallbackJwtProvider.GetTokenCallback;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.StringUtils;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

/**
 * @author Andrii Iakovenko
 *
 */
public class BrainKeyExamplesTest extends ConfigurableTest {

  private CardManager cardManager;
  private String YOUR_IDENTITY;
  private String authenticatedQueryToServerSide;
  private PythiaClient pythiaClient;

  @Before
  public void setup() throws CryptoException {
    String baseUrl = getPythiaServiceUrl();
    if (StringUtils.isBlank(baseUrl)) {
      this.pythiaClient = new VirgilPythiaClient();
    } else {
      this.pythiaClient = new VirgilPythiaClient(baseUrl);
    }

    YOUR_IDENTITY = "Identity-" + UUID.randomUUID().toString();

    authenticatedQueryToServerSide = new JwtGenerator(getAppId(), getApiPrivateKey(),
        getApiPublicKeyId(), TimeSpan.fromTime(1, TimeUnit.HOURS), new VirgilAccessTokenSigner())
            .generateToken(YOUR_IDENTITY).stringRepresentation();

    CardCrypto cardCrypto = new VirgilCardCrypto();
    CardVerifier cardVerifier = new VirgilCardVerifier(cardCrypto);
    AccessTokenProvider accessTokenProvider = new CallbackJwtProvider(new GetTokenCallback() {

      @Override
      public String onGetToken(TokenContext tokenContext) {
        return authenticatedQueryToServerSide;
      }
    });
    cardManager = new CardManager(cardCrypto, accessTokenProvider, cardVerifier);
  }

  @Test
  @Ignore
  public void generate_brainKey()
      throws CryptoException, VirgilServiceException, VirgilPythiaServiceException {
    /** Snippet start. */

    // 1. Specify your JWT provider

    // Get generated token from server-side
    final String authenticatedQueryToServerSide = "eyJraWQiOiI3MGI0NDdlMzIxZjNhMGZkIiwidHlwIjoiSldUIiwiYWxnIjoiVkVEUzUxMiIsImN0eSI6InZpcmdpbC1qd3Q7dj0xIn0.eyJleHAiOjE1MTg2OTg5MTcsImlzcyI6InZpcmdpbC1iZTAwZTEwZTRlMWY0YmY1OGY5YjRkYzg1ZDc5Yzc3YSIsInN1YiI6ImlkZW50aXR5LUFsaWNlIiwiaWF0IjoxNTE4NjEyNTE3fQ.MFEwDQYJYIZIAWUDBAIDBQAEQP4Yo3yjmt8WWJ5mqs3Yrqc_VzG6nBtrW2KIjP-kxiIJL_7Wv0pqty7PDbDoGhkX8CJa6UOdyn3rBWRvMK7p7Ak";

    // Setup AccessTokenProvider
    AccessTokenProvider accessTokenProvider = new CachingJwtProvider(new RenewJwtCallback() {

      @Override
      public Jwt renewJwt(TokenContext tokenContext) {
        return new Jwt(authenticatedQueryToServerSide);
      }
    });

    // 2. Setup BrainKey

    BrainKeyContext brainKeyContext = new BrainKeyContext.Builder()
        .setAccessTokenProvider(accessTokenProvider).setPythiaCrypto(new VirgilPythiaCrypto())
        .setPythiaClient(new VirgilPythiaClient()).build();
    BrainKey brainKey = new BrainKey(brainKeyContext);

    VirgilKeyPair keyPair = brainKey.generateKeyPair("Your password");

    // 3. Publish user's on the Cards Service
    Card card = cardManager.publishCard(keyPair.getPrivateKey(), keyPair.getPublicKey(),
        YOUR_IDENTITY);

    /** Snippet end. */
    assertNotNull(card);
  }

}
