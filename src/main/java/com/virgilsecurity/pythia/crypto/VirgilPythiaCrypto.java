/*
 * Copyright (c) 2015-2019, Virgil Security, Inc.
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

import java.util.concurrent.atomic.AtomicLong;

import com.virgilsecurity.crypto.pythia.Pythia;
import com.virgilsecurity.crypto.pythia.PythiaBlindResult;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * Virgil implementation of all crypto operation needed by Pythia.
 * 
 * @author Andrii Iakovenko
 *
 */
public class VirgilPythiaCrypto implements PythiaCrypto {

  private static final int RANDOM_DATA_SIZE = 32;
  private static final AtomicLong INSTANCE_COUNT = new AtomicLong(0);

  private VirgilCrypto virgilCrypto;

  /**
   * Create a new instance of {@link VirgilPythiaCrypto}.
   *
   */
  public VirgilPythiaCrypto() {
    INSTANCE_COUNT.incrementAndGet();

    this.virgilCrypto = new VirgilCrypto();
    Pythia.configure();
  }

  /*
   * (non-Javadoc)
   * 
   * @see com.virgilsecurity.pythia.crypto.PythiaCrypto#blind(java.lang.String)
   */
  @Override
  public BlindResult blind(String password) {
    PythiaBlindResult blindResult = Pythia.blind(ConvertionUtils.toBytes(password));
    return new BlindResult(blindResult.getBlindedPassword(), blindResult.getBlindingSecret());
  }

  /*
   * (non-Javadoc)
   * 
   * @see com.virgilsecurity.pythia.crypto.PythiaCrypto#deblind(byte[], byte[])
   */
  @Override
  public byte[] deblind(byte[] transformedPassword, byte[] blindingSecret) {
    return Pythia.deblind(transformedPassword, blindingSecret);
  }

  /*
   * (non-Javadoc)
   * 
   * @see com.virgilsecurity.pythia.crypto.PythiaCrypto#verify(byte[], byte[], byte[], byte[],
   * byte[], byte[])
   */
  @Override
  public boolean verify(byte[] transformedPassword, byte[] blindedPassword, byte[] tweak,
      byte[] transformationPublicKey, byte[] proofC, byte[] proofU) {
    return Pythia.verify(transformedPassword,
                         blindedPassword,
                         tweak,
                         transformationPublicKey,
                         proofC,
                         proofU);
  }

  /*
   * (non-Javadoc)
   * 
   * @see com.virgilsecurity.pythia.crypto.PythiaCrypto#updateDeblinded(byte[], byte[])
   */
  @Override
  public byte[] updateDeblinded(byte[] deblindedPassword, byte[] updateToken) {
    return Pythia.updateDeblindedWithToken(deblindedPassword, updateToken);
  }

  /*
   * (non-Javadoc)
   * 
   * @see com.virgilsecurity.pythia.crypto.PythiaCrypto#generateSalt()
   */
  @Override
  public byte[] generateSalt() {
    return virgilCrypto.generateRandomData(RANDOM_DATA_SIZE);
  }

  /*
   * (non-Javadoc)
   * 
   * @see
   * com.virgilsecurity.pythia.crypto.PythiaCrypto#generateKeyPair(com.virgilsecurity.sdk.crypto.
   * KeysType, byte[])
   */
  @Override
  public VirgilKeyPair generateKeyPair(byte[] seed) throws CryptoException {
    return virgilCrypto.generateKeyPair(seed);
  }

  @Override
  protected void finalize() {
    long count = INSTANCE_COUNT.decrementAndGet();
    if (count == 0) {
      Pythia.cleanup();
    }
  }
}
