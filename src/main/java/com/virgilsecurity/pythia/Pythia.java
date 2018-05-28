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
import com.virgilsecurity.pythia.crypto.BlindResult;
import com.virgilsecurity.pythia.crypto.PythiaCrypto;
import com.virgilsecurity.pythia.model.BreachProofPassword;
import com.virgilsecurity.pythia.model.TransformResponse;
import com.virgilsecurity.pythia.model.exception.TransformVerificationException;
import com.virgilsecurity.pythia.model.exception.VirgilPythiaServiceException;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.TokenContext;
import com.virgilsecurity.sdk.jwt.contract.AccessToken;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.Base64;
import com.virgilsecurity.sdk.utils.StringUtils;

import java.util.Arrays;

/**
 * This class is responsible for Pythia password protection interactions.
 * 
 * @author Danylo Oliinyk
 *
 */
public class Pythia {

  private ProofKeys proofKeys;
  private PythiaCrypto pythiaCrypto;
  private PythiaClient pythiaClient;
  private AccessTokenProvider accessTokenProvider;

  /**
   * Create a new instance of {@link Pythia}.
   *
   * @param context
   *          the Pythia-related configuration.
   */
  public Pythia(PythiaContext context) {
    if (context == null) {
      throw new IllegalArgumentException("Context should be set");
    }
    this.proofKeys = context.getProofKeys();
    this.pythiaCrypto = context.getPythiaCrypto();
    this.pythiaClient = context.getPythiaClient();
    this.accessTokenProvider = context.getAccessTokenProvider();
  }

  /**
   * Update an existing Pythia breach proof password.
   * 
   * @param updateToken
   *          the update token. You can get it at developer dashboard.
   * @param breachProofPassword
   *          the breach proof password.
   * @return the update breach proof password.
   */
  public BreachProofPassword updateBreachProofPassword(String updateToken,
      BreachProofPassword breachProofPassword) {
    // Verify update token
    if (StringUtils.isBlank(updateToken)) {
      throw new IllegalArgumentException("Update token should not be empty");
    }
    if (breachProofPassword == null) {
      throw new IllegalArgumentException("Breach proof password should be set");
    }
    String[] parts = updateToken.split("\\.");
    if (parts.length != 4 || !parts[0].equals("UT")) {
      throw new IllegalArgumentException("Update token has invalid format");
    }
    int prevVersion = 0;
    int nextVersion = 0;
    byte[] updateTokenData;
    try {
      prevVersion = Integer.parseInt(parts[1]);
      nextVersion = Integer.parseInt(parts[2]);
      updateTokenData = Base64.decode(parts[3]);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("Update token has invalid format");
    }

    if (nextVersion == breachProofPassword.getVersion()) {
      throw new IllegalArgumentException("Already migrated");
    }
    if (prevVersion != breachProofPassword.getVersion()) {
      throw new IllegalArgumentException("Wrong user version");
    }

    byte[] newDeblindedPassword = this.pythiaCrypto
        .updateDeblinded(breachProofPassword.getDeblindedPassword(), updateTokenData);

    return new BreachProofPassword(breachProofPassword.getSalt(), newDeblindedPassword,
        nextVersion);
  }

  /**
   * Create breach proof password.
   * 
   * @param password
   *          the end user's password.
   * @return the new breach proof password.
   * @throws CryptoException
   *           if some error occurred during crypto operation.
   * @throws TransformVerificationException
   *           if transform response doesn't pass validation/
   * @throws VirgilPythiaServiceException
   *           if Pythia service returned an error.
   */
  public BreachProofPassword createBreachProofPassword(String password)
      throws CryptoException, VirgilPythiaServiceException, TransformVerificationException {
    byte[] salt = this.pythiaCrypto.generateSalt();

    BlindResult blinded = this.pythiaCrypto.blind(password);
    byte[] blindedPassword = blinded.getBlindedPassword();
    byte[] blindingSecret = blinded.getBlindingSecret();

    ProofKey currentProofKey = this.proofKeys.getCurrentKey();

    TokenContext tokenContext = new TokenContext("pythia-java", "transform", false, "pythia");
    AccessToken accessToken = accessTokenProvider.getToken(tokenContext);
    TransformResponse transformResponse = this.pythiaClient.transformPassword(salt, blindedPassword,
        currentProofKey.getVersion(), true, accessToken.stringRepresentation());

    boolean isTransformVerified = pythiaCrypto.verify(transformResponse.getTransformedPassword(),
        blindedPassword, salt, currentProofKey.getData(), transformResponse.getProof().getC(),
        transformResponse.getProof().getU());

    if (!isTransformVerified) {
      throw new TransformVerificationException();
    }

    byte[] deblindedPassword = this.pythiaCrypto.deblind(transformResponse.getTransformedPassword(),
        blindingSecret);

    return new BreachProofPassword(salt, deblindedPassword, currentProofKey.getVersion());
  }

  /**
   * Verify an existing breach proof password.
   * 
   * @param password
   *          the password.
   * @param breachProofPassword
   *          the breach proof password.
   * @param prove
   *          require include proof for transformation from Virgil Pythia server.
   * @return {@code true} if password corresponds to breach proof password.
   * @throws CryptoException
   *           if some error occurred during crypto operation.
   * @throws TransformVerificationException
   *           if transform response doesn't pass validation/
   * @throws VirgilPythiaServiceException
   *           if Pythia service returned an error.
   */
  public boolean verifyBreachProofPassword(String password, BreachProofPassword breachProofPassword,
      boolean prove)
      throws CryptoException, TransformVerificationException, VirgilPythiaServiceException {
    TokenContext tokenContext = new TokenContext("pythia-java", "transform", false, "pythia");
    AccessToken accessToken = accessTokenProvider.getToken(tokenContext);
    BlindResult blinded = pythiaCrypto.blind(password);
    byte[] blindedPassword = blinded.getBlindedPassword();
    byte[] blindingSecret = blinded.getBlindingSecret();
    ProofKey actualProofKey = this.proofKeys.getProofKey(breachProofPassword.getVersion());

    TransformResponse transformResponse = this.pythiaClient.transformPassword(
        breachProofPassword.getSalt(), blindedPassword, breachProofPassword.getVersion(), prove,
        accessToken.stringRepresentation());

    if (prove) {
      boolean isTransformVerified = pythiaCrypto.verify(transformResponse.getTransformedPassword(),
          blindedPassword, breachProofPassword.getSalt(), actualProofKey.getData(),
          transformResponse.getProof().getC(), transformResponse.getProof().getU());
      if (!isTransformVerified) {
        throw new TransformVerificationException();
      }
    }

    byte[] deblindedPassword = this.pythiaCrypto.deblind(transformResponse.getTransformedPassword(),
        blindingSecret);

    return Arrays.equals(deblindedPassword, breachProofPassword.getDeblindedPassword());
  }
}
