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

/**
 * This class represents a request to Virgil Pythia service to generate a seed.
 * 
 * @author Andrii Iakovenko
 *
 */
public class GenerateSeedRequest {

  @SerializedName("blinded_password")
  private byte[] blindedPassword;

  @SerializedName("brainkey_id")
  private String brainkeyId;

  /**
   * Create a new instance of {@link GenerateSeedRequest}.
   *
   * @param blindedPassword
   *          a password obfuscated into a pseudo-random string.
   */
  public GenerateSeedRequest(byte[] blindedPassword) {
    this.blindedPassword = blindedPassword;
  }

  /**
   * Create a new instance of {@link GenerateSeedRequest}.
   *
   * @param blindedPassword
   *          a password obfuscated into a pseudo-random string.
   * @param brainkeyId
   *          Brainkey ID value.
   */
  public GenerateSeedRequest(byte[] blindedPassword, String brainkeyId) {
    this(blindedPassword);
    this.brainkeyId = brainkeyId;
  }

}
