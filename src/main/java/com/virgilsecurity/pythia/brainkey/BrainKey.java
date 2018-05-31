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

import com.virgilsecurity.pythia.crypto.BlindResult;
import com.virgilsecurity.pythia.model.exception.VirgilPythiaServiceException;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.TokenContext;

/**
 * Pythia BrainKey.
 * 
 * @author Andrii Iakovenko
 *
 */
public class BrainKey {

  private BrainKeyContext context;

  /**
   * Create a new instance of {@link BrainKey}.
   *
   * @param context
   *          the context.
   */
  public BrainKey(BrainKeyContext context) {
    this.context = context;
  }

  /**
   * Generates key pair based on given password.
   * 
   * @param password
   *          password from which key pair will be generated.
   * @return generated {@link VirgilKeyPair}.
   * @throws CryptoException
   *           if crypto operation failed.
   * @throws VirgilPythiaServiceException
   *           if Pythia service returned an error.
   */
  public VirgilKeyPair generateKeyPair(String password)
      throws CryptoException, VirgilPythiaServiceException {
    return generateKeyPair(password, null);
  }

  /**
   * Generates key pair based on given password and brainkeyId.
   * 
   * @param password
   *          password from which key pair will be generated.
   * @param brainKeyId
   *          brainKey identifier (in case one wants to generate several key pairs from 1 password).
   * @return generated {@link VirgilKeyPair}.
   * @throws CryptoException
   *           if crypto operation failed.
   * @throws VirgilPythiaServiceException
   *           if Pythia service returned an error.
   */
  public VirgilKeyPair generateKeyPair(String password, String brainKeyId)
      throws CryptoException, VirgilPythiaServiceException {
    String token = this.context.getAccessTokenProvider()
        .getToken(new TokenContext("seed", false, "pythia")).stringRepresentation();

    BlindResult blindedResult = this.context.getPythiaCrypto().blind(password);
    byte[] seed = this.context.getPythiaClient().generateSeed(blindedResult.getBlindedPassword(),
        brainKeyId, token);

    byte[] deblindedPassword = this.context.getPythiaCrypto().deblind(seed,
        blindedResult.getBlindingSecret());
    VirgilKeyPair keyPair = this.context.getPythiaCrypto()
        .generateKeyPair(this.context.getKeyPairType(), deblindedPassword);
    return keyPair;
  }

}
