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

package com.virgilsecurity.pythia.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.virgilsecurity.crypto.pythia.Pythia;
import com.virgilsecurity.crypto.pythia.PythiaBlindResult;
import com.virgilsecurity.crypto.pythia.PythiaComputeTransformationKeyPairResult;
import com.virgilsecurity.crypto.pythia.PythiaProveResult;
import com.virgilsecurity.crypto.pythia.PythiaTransformResult;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import org.apache.commons.lang.ArrayUtils;
import org.junit.Before;
import org.junit.Test;

/**
 * VirgilCryptoPythia class.
 */
public class VirgilCryptoPythiaTest {

  private JsonObject sampleJson;
  private byte[] pythiaSecret;
  private byte[] pythiaScopeSecret;

  @Test
  public void blind() {
    // YTC-3
    byte[] transformationKeyId = getBytes("kTransformationKeyID");
    byte[] password = getBytes("kPassword");
    byte[] tweek = getBytes("kTweek");
    byte[] deblindedPassword = getHexBytes("kDeblindedPassword");

    Set<PythiaBlindResult> blindResults = new HashSet<>();
    for (int i = 0; i < 10; i++) {
      PythiaComputeTransformationKeyPairResult transformationKeyPair = Pythia
          .computeTransformationKeyPair(transformationKeyId, this.pythiaSecret,
              this.pythiaScopeSecret);
      PythiaBlindResult blindResult = Pythia.blind(password);

      // blindResult should be different on each iteration
      for (PythiaBlindResult res : blindResults) {
        if (ArrayUtils.isEquals(res.getBlindedPassword(), blindResult.getBlindedPassword())
            && ArrayUtils.isEquals(res.getBlindingSecret(), blindResult.getBlindingSecret())) {
          fail();
        }
      }
      blindResults.add(blindResult);

      PythiaTransformResult transformResult = Pythia.transform(blindResult.getBlindedPassword(),
          tweek, transformationKeyPair.getTransformationPrivateKey());
      assertNotNull(transformResult);

      byte[] deblindResult = Pythia.deblind(transformResult.getTransformedPassword(),
          blindResult.getBlindingSecret());
      assertArrayEquals(deblindedPassword, deblindResult);
    }
  }

  @Test
  public void computeTransformationKeyPair() {
    byte[] transformationKeyId = getBytes("kTransformationKeyID");

    PythiaComputeTransformationKeyPairResult transformationKeyPair = Pythia
        .computeTransformationKeyPair(transformationKeyId, this.pythiaSecret,
            this.pythiaScopeSecret);

    assertNotNull(transformationKeyPair);
    assertArrayEquals(getHexBytes("kTransformationPrivateKey"),
        transformationKeyPair.getTransformationPrivateKey());
    assertArrayEquals(getHexBytes("kTransformationPublicKey"),
        transformationKeyPair.getTransformationPublicKey());
  }

  @Test
  public void prove() {
    // YTC-4
    byte[] transformationKeyId = getBytes("kTransformationKeyID");
    byte[] password = getBytes("kPassword");
    byte[] tweek = getBytes("kTweek");

    PythiaComputeTransformationKeyPairResult transformationKeyPair = Pythia
        .computeTransformationKeyPair(transformationKeyId, this.pythiaSecret,
            this.pythiaScopeSecret);
    PythiaBlindResult blindResult = Pythia.blind(password);
    PythiaTransformResult transformResult = Pythia.transform(blindResult.getBlindedPassword(),
        tweek, transformationKeyPair.getTransformationPrivateKey());
    PythiaProveResult proveResult = Pythia.prove(transformResult.getTransformedPassword(),
        blindResult.getBlindedPassword(), transformResult.getTransformedTweak(),
        transformationKeyPair.getTransformationPrivateKey(),
        transformationKeyPair.getTransformationPublicKey());
    //    boolean verifyResult = Pythia.verify(transformResult.transformedPassword,
    //                                         blindResult.blindedPassword,
    //                                         tweek,
    //                                         transformationKeyPair.transformationPublicKey,
    //                                         proveResult.proofValueC,
    //                                         proveResult.proofValueU);
    //    assertTrue(verifyResult); // TODO update when fixed in crypto
  }

  @Before
  public void setup() {
    sampleJson = (JsonObject) new JsonParser()
        .parse(new InputStreamReader(Objects.requireNonNull(this.getClass().getClassLoader()
            .getResourceAsStream("com/virgilsecurity/pythia/crypto/pythia-crypto.json"))));
    this.pythiaSecret = getBytes("kPythiaSecret");
    this.pythiaScopeSecret = getBytes("kPythiaScopeSecret");

    // YTC-1
    Pythia.configure();
  }

  @Test
  public void updateDeblindedWithToken() {
    // YTC-5
    final byte[] transformationKeyId = getBytes("kTransformationKeyID");
    final byte[] password = getBytes("kPassword");
    final byte[] tweek = getBytes("kTweek");
    final byte[] newTransformationPrivateKey = getHexBytes("kNewTransformationPrivateKey");
    final byte[] newTransformationPublicKey = getHexBytes("kNewTransformationPublicKey");
    final byte[] updateToken = getHexBytes("kUpdateToken");
    final byte[] newDeblinded = getHexBytes("kNewDeblinded");

    PythiaComputeTransformationKeyPairResult transformationKeyPair = Pythia
        .computeTransformationKeyPair(transformationKeyId, this.pythiaSecret,
            this.pythiaScopeSecret);
    PythiaBlindResult blindResult = Pythia.blind(password);
    PythiaTransformResult transformResult = Pythia.transform(blindResult.getBlindedPassword(),
        tweek, transformationKeyPair.getTransformationPrivateKey());
    final byte[] deblindResult = Pythia.deblind(transformResult.getTransformedPassword(),
        blindResult.getBlindingSecret());

    PythiaComputeTransformationKeyPairResult newTransformationKeyPair = Pythia
        .computeTransformationKeyPair(transformationKeyId, getBytes("kNewPythiaSecret"),
            getBytes("kNewPythiaScopeSecret"));
    assertArrayEquals(newTransformationPrivateKey,
        newTransformationKeyPair.getTransformationPrivateKey());
    assertArrayEquals(newTransformationPublicKey,
        newTransformationKeyPair.getTransformationPublicKey());

    byte[] passwordUpdateTokenResult = Pythia.getPasswordUpdateToken(
        transformationKeyPair.getTransformationPrivateKey(),
        newTransformationKeyPair.getTransformationPrivateKey());
    assertArrayEquals(updateToken, passwordUpdateTokenResult);

    byte[] updatedDeblindPasswordResult = Pythia.updateDeblindedWithToken(deblindResult,
        passwordUpdateTokenResult);
    PythiaTransformResult newTransformResult = Pythia.transform(blindResult.getBlindedPassword(),
        tweek, newTransformationKeyPair.getTransformationPrivateKey());
    byte[] newDeblindResult = Pythia.deblind(newTransformResult.getTransformedPassword(),
        blindResult.getBlindingSecret());
    assertArrayEquals(newDeblinded, updatedDeblindPasswordResult);
    assertArrayEquals(newDeblinded, newDeblindResult);
  }

  private byte[] getBytes(String key) {
    return this.sampleJson.get(key).getAsString().getBytes(StandardCharsets.UTF_8);
  }

  private byte[] getHexBytes(String fromPath) {
    String hexString = this.sampleJson.get(fromPath).getAsString();

    if (hexString.length() % 2 == 1) {
      throw new IllegalArgumentException("Invalid hexadecimal String supplied.");
    }

    byte[] bytes = new byte[hexString.length() / 2];
    for (int i = 0; i < hexString.length(); i += 2) {
      bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
    }
    return bytes;
  }

  private byte hexToByte(String hexString) {
    int firstDigit = toDigit(hexString.charAt(0));
    int secondDigit = toDigit(hexString.charAt(1));
    return (byte) ((firstDigit << 4) + secondDigit);
  }

  private int toDigit(char hexChar) {
    int digit = Character.digit(hexChar, 16);
    if (digit == -1) {
      throw new IllegalArgumentException("Invalid Hexadecimal Character: " + hexChar);
    }
    return digit;
  }
}
