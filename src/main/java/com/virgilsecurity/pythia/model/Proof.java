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

import com.google.gson.annotations.SerializedName;

/**
 * Plain model representing response from Pythia server.
 * 
 * @author Danylo Oliinyk
 *
 */
public final class Proof {

  @SerializedName("value_c")
  private byte[] proofC;

  @SerializedName("value_u")
  private byte[] proofU;

  /**
   * Create a new instance of {@link Proof}.
   *
   */
  public Proof() {
  }

  /**
   * Create a new instance of {@link Proof}.
   *
   * @param c
   *          a first part of proof that transformedPassword was created using
   *          transformationPrivateKey.
   * @param u
   *          a second part of proof that transformedPassword was created using
   *          transformationPrivateKey.
   */
  public Proof(byte[] c, byte[] u) {
    this.proofC = c;
    this.proofU = u;
  }

  /**
   * Get the proof C value.
   * 
   * @return a first part of proof that transformedPassword was created using
   *         transformationPrivateKey.
   */
  public byte[] getC() {
    return proofC;
  }

  /**
   * Get the proof U value.
   * 
   * @return a second part of proof that transformedPassword was created using
   *         transformationPrivateKey.
   */
  public byte[] getU() {
    return proofU;
  }
}
