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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.virgilsecurity.crypto.VirgilPythia;
import com.virgilsecurity.crypto.VirgilPythiaProveResult;
import com.virgilsecurity.crypto.VirgilPythiaTransformResult;
import com.virgilsecurity.crypto.VirgilPythiaTransformationKeyPair;
import com.virgilsecurity.pythia.crypto.BlindResult;
import com.virgilsecurity.pythia.crypto.PythiaCrypto;
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto;
import com.virgilsecurity.pythia.model.BreachProofPassword;
import com.virgilsecurity.pythia.model.exception.ThrottlingException;
import com.virgilsecurity.pythia.model.exception.TransformVerificationException;
import com.virgilsecurity.pythia.model.exception.VirgilPythiaServiceException;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.Base64;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Before;
import org.junit.Test;

/**
 * Integration tests for {@link Pythia}.
 * 
 * @author Andrii Iakovenko
 *
 */
public class PythiaTest extends ConfigurableTest {

  private Pythia pythia;
  private PythiaCrypto pythiaCrypto;
  private String password;
  private SampleDataHolder sample;

  @Before
  public void setup() {
    sample = new SampleDataHolder("com/virgilsecurity/pythia/pythia-sdk.json");
  }

  private void setup(List<String> proofKeys) {
    setup(new VirgilPythiaCrypto(), proofKeys);
  }

  private void setup(PythiaCrypto pythiaCrypto, List<String> proofKeys) {
    PythiaContext context = new PythiaContext.Builder().setAppId(getAppId())
        .setApiKey(getApiPrivateKeyStr()).setApiPublicKeyIdentifier(getApiPublicKeyId())
        .setProofKeys(proofKeys).setPythiaCrypto(pythiaCrypto)
        .setPythiaServiceUrl(getPythiaServiceUrl()).build();

    this.pythia = new Pythia(context);
    this.pythiaCrypto = new VirgilPythiaCrypto();
    this.password = "some password";

    try {
      Thread.sleep(2000);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }

  @Test
  public void createBreachProofPassword()
      throws CryptoException, VirgilPythiaServiceException, TransformVerificationException {
    // YTC-13
    setup(getProofKeys1());

    BreachProofPassword bpp1 = this.pythia.createBreachProofPassword(this.password);
    assertNotNull(bpp1);
    assertNotEmpty("Salt", bpp1.getSalt());
    assertEquals(32, bpp1.getSalt().length);
    assertNotEmpty("Deblinded password", bpp1.getDeblindedPassword());
    assertTrue(bpp1.getDeblindedPassword().length > 300);
    assertEquals(1, bpp1.getVersion());

    BreachProofPassword bpp2 = this.pythia.createBreachProofPassword(this.password);
    assertNotNull(bpp2);
    assertNotEmpty("Salt", bpp2.getSalt());
    assertEquals(32, bpp2.getSalt().length);
    assertNotEmpty("Deblinded password", bpp2.getDeblindedPassword());
    assertTrue(bpp2.getDeblindedPassword().length > 300);
    assertEquals(1, bpp2.getVersion());

    assertFalse(Arrays.equals(bpp1.getSalt(), bpp2.getSalt()));
    assertFalse(Arrays.equals(bpp1.getDeblindedPassword(), bpp2.getDeblindedPassword()));
  }

  @Test
  public void createBreachProofPassword_3keys()
      throws CryptoException, VirgilPythiaServiceException, TransformVerificationException {
    // YTC-14
    setup(getProofKeys3());

    BreachProofPassword bpp = this.pythia.createBreachProofPassword(this.password);
    assertEquals(3, bpp.getVersion());
  }

  @Test
  public void verifyBreachProofPassword() throws CryptoException, VirgilPythiaServiceException,
      TransformVerificationException, InterruptedException {
    // YTC-15
    setup(getProofKeys2());

    BreachProofPassword bpp = this.pythia.createBreachProofPassword(password);
    assertNotNull(bpp);

    Thread.sleep(2000);
    assertTrue(this.pythia.verifyBreachProofPassword(this.password, bpp, false));

    Thread.sleep(2000);
    assertTrue(this.pythia.verifyBreachProofPassword(this.password, bpp, true));

    Thread.sleep(2000);
    assertFalse(this.pythia.verifyBreachProofPassword("other password", bpp, false));

    Thread.sleep(2000);
    assertFalse(this.pythia.verifyBreachProofPassword("other password", bpp, true));
  }

  @Test
  public void verifyBreachProofPassword_stubbedCrypto() throws CryptoException,
      VirgilPythiaServiceException, TransformVerificationException, InterruptedException {
    // YTC-16
    final AtomicBoolean ab = new AtomicBoolean(true);
    setup(new VirgilPythiaCrypto() {
      /*
       * (non-Javadoc)
       * 
       * @see com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto#verify(byte[], byte[], byte[],
       * byte[], byte[], byte[])
       */
      @Override
      public boolean verify(byte[] transformedPassword, byte[] blindedPassword, byte[] tweak,
          byte[] transformationPublicKey, byte[] proofC, byte[] proofU) {
        boolean result = ab.get();
        ab.set(false);
        return result;
      }
    }, getProofKeys2());

    BreachProofPassword bpp = this.pythia.createBreachProofPassword(password);
    assertNotNull(bpp);

    Thread.sleep(2000);
    assertTrue(this.pythia.verifyBreachProofPassword(this.password, bpp, false));

    Thread.sleep(2000);
    try {
      this.pythia.verifyBreachProofPassword(this.password, bpp, true);
      fail();
    } catch (Exception e) {
      // Nothing to do here
    }

    Thread.sleep(2000);
    assertFalse(this.pythia.verifyBreachProofPassword("other password", bpp, false));

    Thread.sleep(2000);
    try {
      this.pythia.verifyBreachProofPassword("other password", bpp, true);
      fail();
    } catch (Exception e) {
      // Nothing to do here
    }
  }

  @Test
  public void verifyBreachProofPassword_noProve() throws CryptoException,
      VirgilPythiaServiceException, TransformVerificationException, InterruptedException {
    setup(getProofKeys1());

    BreachProofPassword breachProofPassword = this.pythia.createBreachProofPassword(password);
    assertNotNull(breachProofPassword);

    Thread.sleep(2000);
    boolean verified = this.pythia.verifyBreachProofPassword(this.password, breachProofPassword,
        false);
    assertTrue(verified);
  }

  @Test
  public void verifyBreachProofPassword_withProve() throws CryptoException,
      VirgilPythiaServiceException, TransformVerificationException, InterruptedException {
    setup(getProofKeys1());

    BreachProofPassword breachProofPassword = this.pythia.createBreachProofPassword(password);
    assertNotNull(breachProofPassword);

    Thread.sleep(2000);
    boolean verified = this.pythia.verifyBreachProofPassword(this.password, breachProofPassword,
        true);
    assertTrue(verified);
  }

  @Test
  public void verifyBreachProofPassword_wrongPasswordNoProve() throws CryptoException,
      VirgilPythiaServiceException, TransformVerificationException, InterruptedException {
    setup(getProofKeys1());

    BreachProofPassword breachProofPassword = this.pythia
        .createBreachProofPassword(UUID.randomUUID().toString());
    assertNotNull(breachProofPassword);

    Thread.sleep(2000);
    boolean verified = this.pythia.verifyBreachProofPassword(this.password, breachProofPassword,
        false);
    assertFalse(verified);
  }

  @Test
  public void verifyBreachProofPassword_wrongPasswordWithProve() throws CryptoException,
      VirgilPythiaServiceException, TransformVerificationException, InterruptedException {
    setup(getProofKeys1());

    BreachProofPassword breachProofPassword = this.pythia
        .createBreachProofPassword(UUID.randomUUID().toString());
    assertNotNull(breachProofPassword);

    Thread.sleep(2000);
    boolean verified = this.pythia.verifyBreachProofPassword(this.password, breachProofPassword,
        true);
    assertFalse(verified);
  }

  @Test
  public void updateBreachProofPassword() throws CryptoException, VirgilPythiaServiceException,
      TransformVerificationException, InterruptedException {
    setup(getProofKeys1());

    String password = "password";
    String domain1 = "virgil.com";
    String username = "alice";
    String msk1 = "master secret";
    String sss1 = "server secret";
    String domain2 = "virgilsecurity.com";
    String msk2 = "super master secret";
    String sss2 = "new server secret";
    String deblinded1 = "13273238e3119262f86d3213b8eb6b99c093ef48737dfcfae96210f7350e096cbc7e6b992"
        + "e4e6f705ac3f0a915d1622c1644596408e3d16126ddfa9ce594e9f361b21ef9c82309e5714c09bcd7f7ec5c"
        + "2666591134c645d45ed8c9703e718ee005fe4b97fc40f69b424728831d0a889cd39be04683dd380daa0df67"
        + "c38279e3b9fe32f6c40780311f2dfbb6e89fc90ef15fb2c7958e387182dc7ef57f716fdd152a58ac1d3f0d1"
        + "9bfa2f789024333976c69fbe9e24b58d6cd8fa49c5f4d642b00f8e390c199f37f7b3125758ef284ae10fd9c"
        + "2da7ea280550baccd55dadd70873a063bcfc9cac9079042af88a543a6cc09aaed6ba4954d6ee8ccc6e11459"
        + "44328266616cd00f8a616f0e79e52ddd2ef970c8ba8f8ffce35505dc643c8e2b6e430a1474a6d043a4daf9b"
        + "62af87c1d45ca994d23f908f7898a3f44ca7bb642122087ca819308b3d8afad17ca1f6148e8750870336ca6"
        + "8eb783c89b0dc9d92392f453c650e9f09232b9fcffd1c2cad24b14d2b4952b7f54552295ce0e854996913c";
    String deblinded2 = "05a00496503c4b36c9fc447c2553387ff3c53417d5c1d2c4183e8cc84ef6fc2aade5e6cf4"
        + "d4e1eda76a024803a9af3c90ffd4b991c959e101f5a18c6c373768942ad1f987d2ca80773e430e203932494"
        + "3a16dfc3a90e03550a3b6dc50aa7f6160b91ade09aa99c712b9d6b6982884247e3eb3bdea58e9cf1201b587"
        + "dfc6df3721a8d74a5c29e06b57c952dc26164300a0defa4fa483fda11514acfcf6ca13c73eaf67f7a8215e7"
        + "a6284e1f575cf05dbf55e08801380519956a15e4c3b97e8e6c04eadee78c9d02318b7321e87c3d393e4e79e"
        + "bed32d89960c1e4c2648b7216bd2d01d67330697804d30fa3c2beaca060165c27020b17c3d6273f7f5146eb"
        + "24d379c97f97e5ee560390c7c7cf19710e056d521a8955ebcfc88dd38af24015c54d060997c10c430c44666"
        + "13e3447229c3c2d3dbcff3e246ecbe9a7641ff13b68c72b691c211a6dc40bc9684f54e388929916eecfbfb4"
        + "76aaf47961413f2695ec985b25de76a8c5d5caa13520ef600b2df69e8574729026a4b5d80461348fb67d05";
    byte[] salt = ConvertionUtils.toBytes(username);

    try (VirgilPythia virgilPythia = new VirgilPythia()) {
      VirgilPythiaTransformationKeyPair transformationKeyPair1 = virgilPythia
          .computeTransformationKeyPair(ConvertionUtils.toBytes(domain1),
              ConvertionUtils.toBytes(msk1), ConvertionUtils.toBytes(sss1));
      VirgilPythiaTransformationKeyPair transformationKeyPair2 = virgilPythia
          .computeTransformationKeyPair(ConvertionUtils.toBytes(domain2),
              ConvertionUtils.toBytes(msk2), ConvertionUtils.toBytes(sss2));

      BlindResult blindResult = this.pythiaCrypto.blind(password);
      VirgilPythiaTransformResult transformResult = virgilPythia
          .transform(blindResult.getBlindedPassword(), salt, transformationKeyPair1.privateKey());
      byte[] deblindedPassword = this.pythiaCrypto.deblind(transformResult.transformedPassword(),
          blindResult.getBlindingSecret());
      assertArrayEquals(ConvertionUtils.hexToBytes(deblinded1), deblindedPassword);

      VirgilPythiaProveResult proveResult = virgilPythia.prove(
          transformResult.transformedPassword(), blindResult.getBlindedPassword(),
          transformResult.transformedTweak(), transformationKeyPair1);

      assertTrue(virgilPythia.verify(transformResult.transformedPassword(),
          blindResult.getBlindedPassword(), salt, transformationKeyPair1.publicKey(),
          proveResult.proofValueC(), proveResult.proofValueU()));

      byte[] passwordUpdateToken = virgilPythia.getPasswordUpdateToken(
          transformationKeyPair1.privateKey(), transformationKeyPair2.privateKey());

      BreachProofPassword breachProofPassword = new BreachProofPassword(salt, deblindedPassword, 1);
      String updateToken = "UT.1.2." + Base64.encode(passwordUpdateToken);
      BreachProofPassword updatedBreachProofPassword = this.pythia
          .updateBreachProofPassword(updateToken, breachProofPassword);
      assertArrayEquals(ConvertionUtils.hexToBytes(deblinded2),
          updatedBreachProofPassword.getDeblindedPassword());
    }
  }

  @Test
  public void updateBreachProofPassword_twoPythias() throws CryptoException,
      VirgilPythiaServiceException, TransformVerificationException, InterruptedException {
    // YTC-17
    setup(getProofKeys2());

    BreachProofPassword bpp1 = this.pythia.createBreachProofPassword(password);
    assertNotNull(bpp1);
    assertEquals(2, bpp1.getVersion());

    Thread.sleep(2000);
    setup(getProofKeys3());
    BreachProofPassword bpp2 = this.pythia.updateBreachProofPassword(getUpdateToken2to3(), bpp1);
    assertNotNull(bpp2);
    assertArrayEquals(bpp1.getSalt(), bpp2.getSalt());
    assertFalse(Arrays.equals(bpp1.getDeblindedPassword(), bpp2.getDeblindedPassword()));
    assertEquals(3, bpp2.getVersion());

    Thread.sleep(2000);
    assertTrue(this.pythia.verifyBreachProofPassword(this.password, bpp1, false));

    Thread.sleep(2000);
    assertTrue(this.pythia.verifyBreachProofPassword(this.password, bpp2, false));
  }

  @Test
  public void updateBreachProofPassword_alreadyMigrated() throws CryptoException,
      VirgilPythiaServiceException, TransformVerificationException, InterruptedException {
    // YTC-18
    setup(getProofKeys3());

    BreachProofPassword bpp1 = this.pythia.createBreachProofPassword(password);
    assertNotNull(bpp1);
    assertEquals(3, bpp1.getVersion());

    Thread.sleep(2000);
    try {
      this.pythia.updateBreachProofPassword(getUpdateToken2to3(), bpp1);
      fail();
    } catch (IllegalArgumentException e) {
      assertEquals("Already migrated", e.getMessage());
    }
  }

  @Test
  public void updateBreachProofPassword_wrongUser() throws CryptoException,
      VirgilPythiaServiceException, TransformVerificationException, InterruptedException {
    // YTC-19
    setup(getProofKeys1());

    BreachProofPassword bpp1 = this.pythia.createBreachProofPassword(password);
    assertNotNull(bpp1);
    assertEquals(1, bpp1.getVersion());

    Thread.sleep(2000);
    try {
      this.pythia.updateBreachProofPassword(getUpdateToken2to3(), bpp1);
      fail();
    } catch (IllegalArgumentException e) {
      assertEquals("Wrong user version", e.getMessage());
    }
  }

  @Test
  public void updateBreachProofPassword_incorrectTokenFormat() throws CryptoException,
      VirgilPythiaServiceException, TransformVerificationException, InterruptedException {
    // YTC-20
    setup(getProofKeys1());

    BreachProofPassword bpp1 = this.pythia.createBreachProofPassword(password);
    assertNotNull(bpp1);
    assertEquals(1, bpp1.getVersion());

    Thread.sleep(2000);
    try {
      this.pythia.updateBreachProofPassword(sample.get("kInvalidUpdateToken"), bpp1);
      fail();
    } catch (IllegalArgumentException e) {
      assertEquals("Update token has invalid format", e.getMessage());
    }
  }

  @Test(expected = ThrottlingException.class)
  public void throttling() throws CryptoException, VirgilPythiaServiceException,
      TransformVerificationException, InterruptedException {
    setup(getProofKeys1());

    BreachProofPassword breachProofPassword = this.pythia.createBreachProofPassword(password);
    assertNotNull(breachProofPassword);

    this.pythia.verifyBreachProofPassword(this.password, breachProofPassword, false);
  }

}
