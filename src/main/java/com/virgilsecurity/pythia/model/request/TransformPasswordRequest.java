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

package com.virgilsecurity.pythia.model.request;

import com.google.gson.annotations.SerializedName;
import com.virgilsecurity.sdk.utils.Validator;

/**
 * This class represents a request to Virgil Pythia service to transform password.
 * 
 * @author Danylo Oliinyk
 *
 */
public class TransformPasswordRequest {

  @SerializedName("blinded_password")
  private byte[] blindedPassword;

  @SerializedName("version")
  private int version;

  @SerializedName("include_proof")
  private boolean includeProof;

  @SerializedName("user_id")
  private byte[] salt;

  /**
   * Create a new instance of {@link TransformPasswordRequest}.
   *
   */
  public TransformPasswordRequest() {
  }

  /**
   * Create a new instance of {@link TransformPasswordRequest}.
   *
   * @param salt
   *          random 32byte salt tied to the user.
   * @param blindedPassword
   *          a password obfuscated into a pseudo-random string.
   * @param version
   *          a password version.
   * @param includeProof
   *          set this flag to {@code true} to include proof into service response.
   */
  public TransformPasswordRequest(byte[] salt, byte[] blindedPassword, int version,
      boolean includeProof) {
    Validator.checkNullAgrument(salt, "TransformPasswordRequest -> 'userId' should not be null");
    Validator.checkEmptyAgrument(salt, "TransformPasswordRequest -> 'userId' should not be empty");
    this.salt = salt;

    Validator.checkNullAgrument(blindedPassword,
        "TransformPasswordRequest -> 'blindedPassword' should not be null");
    Validator.checkEmptyAgrument(blindedPassword,
        "TransformPasswordRequest -> 'blindedPassword' should not be empty");

    this.blindedPassword = blindedPassword;
    this.version = version;
    this.includeProof = includeProof;
  }

  /**
   * Get the salt.
   * 
   * @return the random 32byte salt tied to the user.
   */
  public byte[] getSalt() {
    return salt;
  }

  /**
   * Get the blinded password.
   * 
   * @return the password obfuscated into a pseudo-random string.
   */
  public byte[] getBlindedPassword() {
    return blindedPassword;
  }

  /**
   * Get the password version.
   * 
   * @return the password version.
   */
  public int getVersion() {
    return version;
  }

  /**
   * Get the include proof flag.
   * 
   * @return the include proof flag.
   */
  public boolean getIncludeProof() {
    return includeProof;
  }

  /**
   * Set the include proof flag.
   * 
   * @param includeProof
   *          the include proof flag.
   */
  public void setIncludeProof(boolean includeProof) {
    this.includeProof = includeProof;
  }
}
