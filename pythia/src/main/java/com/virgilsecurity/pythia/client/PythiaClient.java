/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
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

import com.virgilsecurity.pythia.model.TransformResponse;
import com.virgilsecurity.pythia.model.exception.VirgilPythiaServiceException;

/**
 * Interface to abstract from Pythia server interactions.
 * 
 * @author Danylo Oliinyk
 *
 */
public interface PythiaClient {

  /**
   * Make call to Pythia service to transform password.
   * 
   * @param salt The salt.
   * @param blindedPassword The blinded password.
   * @param version The key version.
   * @param includeProof Set this flag to {@code true} if you need proof data in request.
   * @param token The authorization token.
   *
   * @return The plain model representing response from Pythia server.
   *
   * @throws VirgilPythiaServiceException If transformPassword is not successful.
   */
  TransformResponse transformPassword(byte[] salt,
                                      byte[] blindedPassword,
                                      Integer version,
                                      boolean includeProof,
                                      String token) throws VirgilPythiaServiceException;

  /**
   * Generates seed using given blinded password and brainkey id.
   * 
   * @param blindedPassword Blinded password.
   * @param brainKeyId Brainkey id.
   * @param token Authorization token.
   *
   * @return Generated seed.
   */
  byte[] generateSeed(byte[] blindedPassword, String brainKeyId, String token)
      throws VirgilPythiaServiceException;
}
