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

package com.virgilsecurity.pythia.client;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.virgilsecurity.pythia.ConfigurableTest;
import com.virgilsecurity.pythia.ProofKeys;
import com.virgilsecurity.pythia.crypto.BlindResult;
import com.virgilsecurity.pythia.crypto.PythiaCrypto;
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto;
import com.virgilsecurity.pythia.model.TransformResponse;
import com.virgilsecurity.pythia.model.exception.VirgilPythiaServiceException;
import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.JwtGenerator;
import com.virgilsecurity.sdk.jwt.TokenContext;
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.StringUtils;

import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Test;

/**
 * Integration tests for {@link VirgilPythiaClient}.
 * 
 * @author Andrii Iakovenko
 *
 */
public class VirgilPythiaClientTest extends ConfigurableTest {

  private PythiaCrypto pythiaCrypto;
  private PythiaClient client;
  private AccessTokenProvider accessTokenProvider;
  private String identity;

  @Before
  public void setup() {
    String baseUrl = getPythiaServiceUrl();
    if (StringUtils.isBlank(baseUrl)) {
      this.client = new VirgilPythiaClient();
    } else {
      this.client = new VirgilPythiaClient(baseUrl);
    }

    this.pythiaCrypto = new VirgilPythiaCrypto();

    this.identity = "pythia_user_" + UUID.randomUUID().toString();
    JwtGenerator generator = new JwtGenerator(getAppId(), getApiPrivateKey(), getApiPublicKeyId(),
        TimeSpan.fromTime(1, TimeUnit.HOURS), new VirgilAccessTokenSigner());
    this.accessTokenProvider = new GeneratorJwtProvider(generator, identity);
  }

  @Test
  public void transformPassword_withProof() throws VirgilPythiaServiceException, CryptoException {
    // YTC-10
    byte[] salt = this.pythiaCrypto.generateSalt();
    String password = UUID.randomUUID().toString();
    int version = 1;
    boolean includeProof = true;
    String token = this.accessTokenProvider
        .getToken(new TokenContext("pythia-java", "transform", false, "pythia"))
        .stringRepresentation();

    BlindResult blindResult = this.pythiaCrypto.blind(password);

    TransformResponse transformResponse = this.client.transformPassword(salt,
        blindResult.getBlindedPassword(), version, includeProof, token);
    assertNotNull(transformResponse);
    assertNotEmpty("Transformed password", transformResponse.getTransformedPassword());
    assertNotNull(transformResponse.getProof());
    assertNotEmpty("Proof value C", transformResponse.getProof().getC());
    assertNotEmpty("Proof value U", transformResponse.getProof().getU());

    byte[] deblindedPassword = this.pythiaCrypto.deblind(transformResponse.getTransformedPassword(),
        blindResult.getBlindingSecret());
    assertNotEmpty("Deblinded password", deblindedPassword);

    ProofKeys proofKeys = new ProofKeys(getProofKeys1());
    boolean verified = this.pythiaCrypto.verify(transformResponse.getTransformedPassword(),
        blindResult.getBlindedPassword(), salt, proofKeys.getCurrentKey().getData(),
        transformResponse.getProof().getC(), transformResponse.getProof().getU());
    assertTrue(verified);
  }

  @Test
  public void transformPassword_withProof_multitime()
      throws VirgilPythiaServiceException, CryptoException, InterruptedException {
    // YTC-11
    byte[] salt = this.pythiaCrypto.generateSalt();
    String password = UUID.randomUUID().toString();
    int version = 1;
    boolean includeProof = true;
    String token = this.accessTokenProvider
        .getToken(new TokenContext("pythia-java", "transform", false, "pythia"))
        .stringRepresentation();

    BlindResult blindResult = this.pythiaCrypto.blind(password);

    TransformResponse transformResponse1 = this.client.transformPassword(salt,
        blindResult.getBlindedPassword(), version, includeProof, token);
    assertNotNull(transformResponse1);
    assertNotEmpty("Transformed password", transformResponse1.getTransformedPassword());
    assertNotNull(transformResponse1.getProof());
    assertNotEmpty("Proof value C", transformResponse1.getProof().getC());
    assertNotEmpty("Proof value U", transformResponse1.getProof().getU());

    byte[] deblindedPassword1 = this.pythiaCrypto
        .deblind(transformResponse1.getTransformedPassword(), blindResult.getBlindingSecret());
    assertNotEmpty("Deblinded password", deblindedPassword1);

    ProofKeys proofKeys = new ProofKeys(getProofKeys1());
    boolean verified = this.pythiaCrypto.verify(transformResponse1.getTransformedPassword(),
        blindResult.getBlindedPassword(), salt, proofKeys.getCurrentKey().getData(),
        transformResponse1.getProof().getC(), transformResponse1.getProof().getU());
    assertTrue(verified);

    Thread.sleep(2000);
    TransformResponse transformResponse2 = this.client.transformPassword(salt,
        blindResult.getBlindedPassword(), version, includeProof, token);
    assertNotNull(transformResponse2);
    assertNotEmpty("Transformed password", transformResponse2.getTransformedPassword());
    assertNotNull(transformResponse1.getProof());
    assertNotEmpty("Proof value C", transformResponse2.getProof().getC());
    assertNotEmpty("Proof value U", transformResponse2.getProof().getU());
    assertFalse(
        Arrays.equals(transformResponse1.getProof().getC(), transformResponse2.getProof().getC()));
    assertFalse(
        Arrays.equals(transformResponse1.getProof().getU(), transformResponse2.getProof().getU()));

    byte[] deblindedPassword2 = this.pythiaCrypto
        .deblind(transformResponse2.getTransformedPassword(), blindResult.getBlindingSecret());
    assertNotEmpty("Deblinded password", deblindedPassword2);
    assertArrayEquals(deblindedPassword1, deblindedPassword2);

    verified = this.pythiaCrypto.verify(transformResponse2.getTransformedPassword(),
        blindResult.getBlindedPassword(), salt, proofKeys.getCurrentKey().getData(),
        transformResponse2.getProof().getC(), transformResponse2.getProof().getU());
    assertTrue(verified);
  }

  @Test
  public void transformPassword_noProof() throws VirgilPythiaServiceException, CryptoException {
    // YTC-9
    byte[] salt = this.pythiaCrypto.generateSalt();
    String password = UUID.randomUUID().toString();
    int version = 1;
    boolean includeProof = false;
    String token = this.accessTokenProvider
        .getToken(new TokenContext("pythia-java", "transform", false, "pythia"))
        .stringRepresentation();

    BlindResult blindResult = this.pythiaCrypto.blind(password);

    TransformResponse transformResponse = this.client.transformPassword(salt,
        blindResult.getBlindedPassword(), version, includeProof, token);
    assertNotNull(transformResponse);
    assertNotEmpty("Transformed password", transformResponse.getTransformedPassword());
    assertNull(transformResponse.getProof());

    byte[] deblindedPassword = this.pythiaCrypto.deblind(transformResponse.getTransformedPassword(),
        blindResult.getBlindingSecret());
    assertNotEmpty("Deblinded password", deblindedPassword);
  }

  @Test
  public void transformPassword_noProof_multipassword()
      throws VirgilPythiaServiceException, CryptoException, InterruptedException {
    // YTC-12
    byte[] salt = this.pythiaCrypto.generateSalt();
    int version = 1;
    boolean includeProof = false;
    String token = this.accessTokenProvider
        .getToken(new TokenContext("pythia-java", "transform", false, "pythia"))
        .stringRepresentation();

    BlindResult blindResult1 = this.pythiaCrypto.blind("some password");
    TransformResponse transformResponse1 = this.client.transformPassword(salt,
        blindResult1.getBlindedPassword(), version, includeProof, token);
    byte[] deblindedPassword1 = this.pythiaCrypto
        .deblind(transformResponse1.getTransformedPassword(), blindResult1.getBlindingSecret());

    Thread.sleep(2000);
    BlindResult blindResult2 = this.pythiaCrypto.blind("some password");
    TransformResponse transformResponse2 = this.client.transformPassword(salt,
        blindResult2.getBlindedPassword(), version, includeProof, token);
    byte[] deblindedPassword2 = this.pythiaCrypto
        .deblind(transformResponse2.getTransformedPassword(), blindResult2.getBlindingSecret());
    assertArrayEquals(deblindedPassword1, deblindedPassword2);

    Thread.sleep(2000);
    BlindResult blindResult3 = this.pythiaCrypto.blind("another password");
    TransformResponse transformResponse3 = this.client.transformPassword(salt,
        blindResult3.getBlindedPassword(), version, includeProof, token);
    byte[] deblindedPassword3 = this.pythiaCrypto
        .deblind(transformResponse3.getTransformedPassword(), blindResult3.getBlindingSecret());
    assertFalse(Arrays.equals(deblindedPassword2, deblindedPassword3));
  }

  @Test
  public void generateSeed_nullBrainKeyId() throws CryptoException, VirgilPythiaServiceException {
    String token = this.accessTokenProvider.getToken(new TokenContext("seed", false, "pythia"))
        .stringRepresentation();

    BlindResult blindResult = this.pythiaCrypto.blind("some password");
    byte[] seed = this.client.generateSeed(blindResult.getBlindedPassword(), null, token);
    assertNotNull(seed);
    assertNotEquals(0, seed.length);
  }

}
