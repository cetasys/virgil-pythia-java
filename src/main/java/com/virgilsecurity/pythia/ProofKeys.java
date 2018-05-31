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

import com.virgilsecurity.pythia.model.exception.ProofKeyNotFoundException;
import com.virgilsecurity.pythia.model.exception.ProofKeyParseException;
import com.virgilsecurity.sdk.utils.Base64;
import com.virgilsecurity.sdk.utils.StringUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Contains Pythia public keys.
 * 
 * @author Andrii Iakovenko
 *
 */
public class ProofKeys {

  private List<ProofKey> proofKeys;

  /**
   * Create a new instance of {@link ProofKeys}.
   * 
   * @param proofKeys
   *          list of Pythia public keys. Key format is 'PK.&lt;version&gt;.&lt;Base64-encoded
   *          data&gt;'.
   */
  public ProofKeys(List<String> proofKeys) {
    if (proofKeys == null || proofKeys.isEmpty()) {
      throw new IllegalArgumentException("No public keys found");
    }

    this.proofKeys = new ArrayList<>(proofKeys.size());
    for (String proofKey : proofKeys) {
      this.proofKeys.add(parsePublicKey(proofKey));
    }
    Collections.sort(this.proofKeys, new Comparator<ProofKey>() {

      @Override
      public int compare(ProofKey pk1, ProofKey pk2) {
        return pk2.getVersion() - pk1.getVersion();
      }
    });
  }

  /**
   * Get the current Pythia public key.
   * 
   * @return the current Pythia public key.
   * @throws ProofKeyNotFoundException
   *           if key not found.
   */
  public ProofKey getCurrentKey() {
    if (this.proofKeys.isEmpty()) {
      throw new ProofKeyNotFoundException();
    }
    return this.proofKeys.get(0);
  }

  /**
   * Find Pythia public key by version.
   * 
   * @param version
   *          the key version for search.
   * @return the Pythia public key.
   * @throws ProofKeyNotFoundException
   *           if key not found.
   */
  public ProofKey getProofKey(int version) {
    for (ProofKey proofKey : this.proofKeys) {
      if (proofKey.getVersion() == version) {
        return proofKey;
      }
    }
    throw new ProofKeyNotFoundException();
  }

  private ProofKey parsePublicKey(String publicKeyStr) {
    if (StringUtils.isBlank(publicKeyStr)) {
      throw new ProofKeyParseException();
    }
    String[] parts = publicKeyStr.split("\\.");
    if (parts.length == 3 && "PK".equals(parts[0])) {
      try {
        int version = Integer.parseInt(parts[1]);
        byte[] data = Base64.decode(parts[2]);
        if (data.length == 0) {
          throw new ProofKeyParseException();
        }
        return new ProofKey(data, version);
      } catch (IllegalArgumentException e) {
        throw new ProofKeyParseException();
      }
    }
    throw new ProofKeyParseException();
  }

}
