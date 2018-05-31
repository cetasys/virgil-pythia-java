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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto;
import com.virgilsecurity.pythia.model.BreachProofPassword;
import com.virgilsecurity.pythia.model.exception.TransformVerificationException;
import com.virgilsecurity.pythia.model.exception.VirgilPythiaServiceException;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

import org.junit.Test;

/**
 * Integration test which covers documentation snippets.
 * 
 * @author Andrii Iakovenko
 *
 */
public class PythiaExamplesTest extends ConfigurableTest {

  @Test
  public void pythia_parameters() throws Exception {
    Pythia pythia = sdkConfiguration();
    BreachProofPassword pwd = createBreachProofPassword(pythia);
    Thread.sleep(2000);
    verifyBreachProofPassword(pythia, pwd);
  }

  private Pythia sdkConfiguration() {
    /** Snippet start. */

    // here set your Virgil Account and Pythia Application credentials
    PythiaContext context = new PythiaContext.Builder() //
        .setPythiaServiceUrl(getPythiaServiceUrl()) /**
                                                     * Remove this line from code snippet
                                                     */
        .setAppId(getAppId()).setApiPublicKeyIdentifier(getApiPublicKeyId())
        .setApiKey(getApiPrivateKeyStr()).setProofKeys(getProofKeys1())
        .setPythiaCrypto(new VirgilPythiaCrypto()).build();

    Pythia pythia = new Pythia(context);

    /** Snippet end. */
    return pythia;
  }

  private BreachProofPassword createBreachProofPassword(Pythia pythia)
      throws CryptoException, VirgilPythiaServiceException, TransformVerificationException {
    /** Snippet start. */

    // create a new Breach-proof password using user's password or its hash
    BreachProofPassword pwd = pythia.createBreachProofPassword("USER_PASSWORD");

    // save Breach-proof password parameters into your users DB

    /** Snippet end. */

    assertNotNull(pwd);
    return pwd;
  }

  private void verifyBreachProofPassword(Pythia pythia, BreachProofPassword pwd) throws Exception {
    /** Snippet start. */

    // get user's Breach-proof password parameters from your users DB

    // ...

    // calculate user's Breach-proof password parameters
    // compare these parameters with parameters from your DB
    boolean isValid = pythia.verifyBreachProofPassword("USER_PASSWORD", pwd, true);

    if (!isValid) {
      throw new Exception("Authentication failed");
    }

    /** Snippet end. */

    assertTrue(isValid);
  }

  @SuppressWarnings("unused")
  private void updateBreachProofPassword(Pythia pythia, BreachProofPassword pwd) {
    /** Snippet start. */
    // get previous user's VerifyBreachProofPassword parameters from a
    // compromised DB

    // ...

    // set up an updateToken that you got on the Virgil Dashboard
    // update previous user's Breach-proof password, and save new one into
    // your DB

    BreachProofPassword updatedPwd = pythia.updateBreachProofPassword("UT.1.2.UPDATE_TOKEN", pwd);
    /** Snippet end. */

    assertNotNull(updatedPwd);
  }

}
