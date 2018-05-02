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

import java.util.Arrays;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.crypto.VirgilPythia;
import com.virgilsecurity.crypto.VirgilPythiaProveResult;
import com.virgilsecurity.crypto.VirgilPythiaTransformResult;
import com.virgilsecurity.crypto.VirgilPythiaTransformationKeyPair;
import com.virgilsecurity.pythia.crypto.BlindResult;
import com.virgilsecurity.pythia.crypto.PythiaCrypto;
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto;
import com.virgilsecurity.pythia.model.BreachProofPassword;
import com.virgilsecurity.pythia.model.exception.TransformVerificationException;
import com.virgilsecurity.pythia.model.exception.VirgilPythiaServiceException;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.Base64;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class PythiaTest extends ConfigurableTest {

	private Pythia pythia;
	private PythiaCrypto pythiaCrypto;
	private String password;

	@Before
	public void setup() {
		PythiaContext context = new PythiaContext.Builder().setAppId(getAppId()).setApiKey(getApiPrivateKeyStr())
				.setApiPublicKeyIdentifier(getApiPublicKeyId()).setProofKeys(Arrays.asList(getProofKey()))
				.setPythiaCrypto(new VirgilPythiaCrypto()).setPythiaServiceUrl(getPythiaServiceUrl()).build();

		this.pythia = new Pythia(context);
		this.pythiaCrypto = new VirgilPythiaCrypto();
		this.password = UUID.randomUUID().toString();
	}

	@Test
	public void createBreachProofPassword()
			throws CryptoException, VirgilPythiaServiceException, TransformVerificationException {
		BreachProofPassword breachProofPassword = this.pythia.createBreachProofPassword(this.password);
		assertNotNull(breachProofPassword);
		assertNotEmpty("Salt", breachProofPassword.getSalt());
		assertNotEmpty("Deblinded password", breachProofPassword.getDeblindedPassword());
		assertEquals(1, breachProofPassword.getVersion());
	}

	@Test
	public void verifyBreachProofPassword_noProve()
			throws CryptoException, VirgilPythiaServiceException, TransformVerificationException {
		BreachProofPassword breachProofPassword = this.pythia.createBreachProofPassword(password);
		assertNotNull(breachProofPassword);

		boolean verified = this.pythia.verifyBreachProofPassword(this.password, breachProofPassword, false);
		assertTrue(verified);
	}

	@Test
	public void verifyBreachProofPassword_withProve()
			throws CryptoException, VirgilPythiaServiceException, TransformVerificationException {
		BreachProofPassword breachProofPassword = this.pythia.createBreachProofPassword(password);
		assertNotNull(breachProofPassword);

		boolean verified = this.pythia.verifyBreachProofPassword(this.password, breachProofPassword, true);
		assertTrue(verified);
	}

	@Test
	public void verifyBreachProofPassword_wrongPasswordNoProve()
			throws CryptoException, VirgilPythiaServiceException, TransformVerificationException {
		BreachProofPassword breachProofPassword = this.pythia.createBreachProofPassword(UUID.randomUUID().toString());
		assertNotNull(breachProofPassword);

		boolean verified = this.pythia.verifyBreachProofPassword(this.password, breachProofPassword, false);
		assertFalse(verified);
	}

	@Test
	public void verifyBreachProofPassword_wrongPasswordWithProve()
			throws CryptoException, VirgilPythiaServiceException, TransformVerificationException {
		BreachProofPassword breachProofPassword = this.pythia.createBreachProofPassword(UUID.randomUUID().toString());
		assertNotNull(breachProofPassword);

		boolean verified = this.pythia.verifyBreachProofPassword(this.password, breachProofPassword, true);
		assertFalse(verified);
	}

	@Test
	public void updateBreachProofPassword()
			throws CryptoException, VirgilPythiaServiceException, TransformVerificationException {
		String password = "password";
		String domain1 = "virgil.com";
		String username = "alice";
		String msk1 = "master secret";
		String sss1 = "server secret";
		String domain2 = "virgilsecurity.com";
		String msk2 = "super master secret";
		String sss2 = "new server secret";
		String deblinded1 = "13273238e3119262f86d3213b8eb6b99c093ef48737dfcfae96210f7350e096cbc7e6b992e4e6f705ac3f0a915d1622c1644596408e3d16126ddfa9ce594e9f361b21ef9c82309e5714c09bcd7f7ec5c2666591134c645d45ed8c9703e718ee005fe4b97fc40f69b424728831d0a889cd39be04683dd380daa0df67c38279e3b9fe32f6c40780311f2dfbb6e89fc90ef15fb2c7958e387182dc7ef57f716fdd152a58ac1d3f0d19bfa2f789024333976c69fbe9e24b58d6cd8fa49c5f4d642b00f8e390c199f37f7b3125758ef284ae10fd9c2da7ea280550baccd55dadd70873a063bcfc9cac9079042af88a543a6cc09aaed6ba4954d6ee8ccc6e1145944328266616cd00f8a616f0e79e52ddd2ef970c8ba8f8ffce35505dc643c8e2b6e430a1474a6d043a4daf9b62af87c1d45ca994d23f908f7898a3f44ca7bb642122087ca819308b3d8afad17ca1f6148e8750870336ca68eb783c89b0dc9d92392f453c650e9f09232b9fcffd1c2cad24b14d2b4952b7f54552295ce0e854996913c";
		String deblinded2 = "05a00496503c4b36c9fc447c2553387ff3c53417d5c1d2c4183e8cc84ef6fc2aade5e6cf4d4e1eda76a024803a9af3c90ffd4b991c959e101f5a18c6c373768942ad1f987d2ca80773e430e2039324943a16dfc3a90e03550a3b6dc50aa7f6160b91ade09aa99c712b9d6b6982884247e3eb3bdea58e9cf1201b587dfc6df3721a8d74a5c29e06b57c952dc26164300a0defa4fa483fda11514acfcf6ca13c73eaf67f7a8215e7a6284e1f575cf05dbf55e08801380519956a15e4c3b97e8e6c04eadee78c9d02318b7321e87c3d393e4e79ebed32d89960c1e4c2648b7216bd2d01d67330697804d30fa3c2beaca060165c27020b17c3d6273f7f5146eb24d379c97f97e5ee560390c7c7cf19710e056d521a8955ebcfc88dd38af24015c54d060997c10c430c4466613e3447229c3c2d3dbcff3e246ecbe9a7641ff13b68c72b691c211a6dc40bc9684f54e388929916eecfbfb476aaf47961413f2695ec985b25de76a8c5d5caa13520ef600b2df69e8574729026a4b5d80461348fb67d05";
		byte[] salt = ConvertionUtils.toBytes(username);

		try (VirgilPythia virgilPythia = new VirgilPythia()) {
			VirgilPythiaTransformationKeyPair transformationKeyPair1 = virgilPythia.computeTransformationKeyPair(
					ConvertionUtils.toBytes(domain1), ConvertionUtils.toBytes(msk1), ConvertionUtils.toBytes(sss1));
			VirgilPythiaTransformationKeyPair transformationKeyPair2 = virgilPythia.computeTransformationKeyPair(
					ConvertionUtils.toBytes(domain2), ConvertionUtils.toBytes(msk2), ConvertionUtils.toBytes(sss2));

			BlindResult blindResult = this.pythiaCrypto.blind(password);
			VirgilPythiaTransformResult transformResult = virgilPythia.transform(blindResult.getBlindedPassword(), salt,
					transformationKeyPair1.privateKey());
			byte[] deblindedPassword = this.pythiaCrypto.deblind(transformResult.transformedPassword(),
					blindResult.getBlindingSecret());
			assertArrayEquals(ConvertionUtils.hexToBytes(deblinded1), deblindedPassword);

			VirgilPythiaProveResult proveResult = virgilPythia.prove(transformResult.transformedPassword(),
					blindResult.getBlindedPassword(), transformResult.transformedTweak(), transformationKeyPair1);

			assertTrue(virgilPythia.verify(transformResult.transformedPassword(), blindResult.getBlindedPassword(),
					salt, transformationKeyPair1.publicKey(), proveResult.proofValueC(), proveResult.proofValueU()));

			byte[] passwordUpdateToken = virgilPythia.getPasswordUpdateToken(transformationKeyPair1.privateKey(),
					transformationKeyPair2.privateKey());

			BreachProofPassword breachProofPassword = new BreachProofPassword(salt, deblindedPassword, 1);
			String updateToken = "UT.1.2." + Base64.encode(passwordUpdateToken);
			BreachProofPassword updatedBreachProofPassword = this.pythia.updateBreachProofPassword(updateToken,
					breachProofPassword);
			assertArrayEquals(ConvertionUtils.hexToBytes(deblinded2),
					updatedBreachProofPassword.getDeblindedPassword());
		}
	}

}
