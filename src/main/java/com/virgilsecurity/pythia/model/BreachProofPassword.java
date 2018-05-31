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

package com.virgilsecurity.pythia.model;

/**
 * Represents Pythia-related info about some user.
 * 
 * @author Danylo Oliinyk
 *
 */
public final class BreachProofPassword {

  private final byte[] salt;
  private final byte[] deblindedPassword;
  private final int version;

  /**
   * Create a new instance of {@link BreachProofPassword}.
   *
   * @param salt
   *          random 32byte salt tied to the user.
   * @param deblindedPassword
   *          deblinded transformedPassword value. This value is not equal to password and is
   *          zero-knowledge protected.
   * @param version
   *          the password version.
   */
  public BreachProofPassword(byte[] salt, byte[] deblindedPassword, int version) {
    this.salt = salt;
    this.deblindedPassword = deblindedPassword;
    this.version = version;
  }

  /**
   * Get the salt.
   * 
   * @return random 32byte salt tied to the user.
   */
  public byte[] getSalt() {
    return salt;
  }

  /**
   * Get deblinded transformedPassword value.
   * 
   * @return deblinded transformedPassword value. This value is not equal to password and is
   *         zero-knowledge protected.
   */
  public byte[] getDeblindedPassword() {
    return deblindedPassword;
  }

  /**
   * Get password version.
   * 
   * @return the version.
   */
  public int getVersion() {
    return version;
  }
}
