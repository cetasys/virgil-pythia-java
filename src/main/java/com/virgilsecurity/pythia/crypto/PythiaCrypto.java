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

import com.virgilsecurity.sdk.crypto.KeysType;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

/**
 * Interface for all crypto operation needed by Pythia.
 * 
 * @author Andrii Iakovenko
 *
 */
public interface PythiaCrypto {

  /**
   * Turns password into a pseudo-random string.
   * 
   * @param password
   *          Random end user's password.
   * @return {@link BlindResult} which contains pair of blinded password and blinding secret.
   */
  BlindResult blind(String password);

  /**
   * Unmasks transformedPassword value with previously returned blindingSecret from
   * {@linkplain #blind(String)}.
   * 
   * @param transformedPassword
   *          the blindedPassword, protected using server secret.
   * @param blindingSecret
   *          the secret random used to blind user's password.
   * @return protected deblinded password.
   */
  byte[] deblind(byte[] transformedPassword, byte[] blindingSecret);

  /**
   * This operation allows client to verify that transform result is correct, assuming the client
   * has previously stored tweak.
   * 
   * @param transformedPassword
   *          the blindedPassword, protected using server secret.
   * @param blindedPassword
   *          a blinded password returned from {@linkplain #blind(String)}
   * @param tweak
   *          the random 32byte salt.
   * @param transformationPublicKey
   *          the public key corresponding to transformationPrivateKey value.
   * @param proofC
   *          the first part of proof that transformedPassword was created using
   *          transformationPrivateKey.
   * @param proofU
   *          the second part of proof that transformedPassword was created using
   *          transformationPrivateKey.
   * @return {@code true} if verification success.
   */
  boolean verify(byte[] transformedPassword, byte[] blindedPassword, byte[] tweak,
      byte[] transformationPublicKey, byte[] proofC, byte[] proofU);

  /**
   * Updates previously stored deblindedPassword with passwordUpdateToken. After this call,
   * transform called with new arguments will return corresponding values.
   * 
   * @param deblindedPassword
   *          a value corresponding to a password, protected by Pythia service with transform
   *          operation.
   * @param updateToken
   *          an update token.
   * @return deblinded protected password updated with token.
   */
  byte[] updateDeblinded(byte[] deblindedPassword, byte[] updateToken);

  /**
   * Generate salt.
   * 
   * @return the random salt.
   */
  byte[] generateSalt();

  /**
   * Generates key pair of given type using random seed.
   * 
   * @param type
   *          type of key pair.
   * @param seed
   *          random seed.
   * @return generated key pair.
   * @throws CryptoException
   *           if crypto operation failed.
   */
  VirgilKeyPair generateKeyPair(KeysType type, byte[] seed) throws CryptoException;

}
