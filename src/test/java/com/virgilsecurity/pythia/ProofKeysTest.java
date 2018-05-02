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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Test;

import com.virgilsecurity.pythia.model.exception.ProofKeyNotFoundException;
import com.virgilsecurity.pythia.model.exception.ProofKeyParseException;
import com.virgilsecurity.sdk.utils.Base64;

/**
 * @author Andrii Iakovenko
 *
 */
public class ProofKeysTest {

	@Test(expected = IllegalArgumentException.class)
	public void instantiate_null() {
		new ProofKeys(null);
	}

	@SuppressWarnings("unchecked")
	@Test(expected = IllegalArgumentException.class)
	public void instantiate_empty() {
		new ProofKeys(Collections.EMPTY_LIST);
	}

	@Test(expected = ProofKeyParseException.class)
	public void instantiate_trash() {
		new ProofKeys(Arrays.asList("12345"));
	}

	@Test
	public void instantiate_singleKey() {
		ProofKeys proofKeys = new ProofKeys(Arrays.asList("PK.1.a2V5IDEgZGF0YQ=="));

		ProofKey key = proofKeys.getCurrentKey();
		verifyKey(key, "a2V5IDEgZGF0YQ==", 1);

		key = proofKeys.getProofKey(1);
		verifyKey(key, "a2V5IDEgZGF0YQ==", 1);

		try {
			key = proofKeys.getProofKey(2);
			fail();
		} catch (ProofKeyNotFoundException e) {
		}
	}

	@Test
	public void instantiate_orderedKeys() {
		List<String> keys = Arrays.asList("PK.0.a2V5IDAgZGF0YQ==", "PK.1.a2V5IDEgZGF0YQ==", "PK.2.a2V5IDIgZGF0YQ==");
		ProofKeys proofKeys = new ProofKeys(keys);

		ProofKey key = proofKeys.getCurrentKey();
		verifyKey(key, "a2V5IDIgZGF0YQ==", 2);

		key = proofKeys.getProofKey(2);
		verifyKey(key, "a2V5IDIgZGF0YQ==", 2);

		key = proofKeys.getProofKey(0);
		verifyKey(key, "a2V5IDAgZGF0YQ==", 0);

		key = proofKeys.getProofKey(1);
		verifyKey(key, "a2V5IDEgZGF0YQ==", 1);

		try {
			key = proofKeys.getProofKey(3);
			fail();
		} catch (ProofKeyNotFoundException e) {
		}
	}

	@Test
	public void instantiate_unorderedKeys() {
		List<String> keys = Arrays.asList("PK.1.a2V5IDEgZGF0YQ==", "PK.2.a2V5IDIgZGF0YQ==", "PK.0.a2V5IDAgZGF0YQ==");
		ProofKeys proofKeys = new ProofKeys(keys);

		ProofKey key = proofKeys.getCurrentKey();
		verifyKey(key, "a2V5IDIgZGF0YQ==", 2);

		key = proofKeys.getProofKey(2);
		verifyKey(key, "a2V5IDIgZGF0YQ==", 2);

		key = proofKeys.getProofKey(0);
		verifyKey(key, "a2V5IDAgZGF0YQ==", 0);

		key = proofKeys.getProofKey(1);
		verifyKey(key, "a2V5IDEgZGF0YQ==", 1);

		try {
			key = proofKeys.getProofKey(3);
			fail();
		} catch (ProofKeyNotFoundException e) {
		}
	}

	@Test(expected = ProofKeyParseException.class)
	public void instantiate_invalidKeyPrefix() {
		new ProofKeys(Arrays.asList("PV.1.a2V5IDEgZGF0YQ=="));
	}
	
	@Test(expected = ProofKeyParseException.class)
	public void instantiate_invalidKeyVersion() {
		new ProofKeys(Arrays.asList("PK.v1.a2V5IDEgZGF0YQ=="));
	}
	
	@Test(expected = ProofKeyParseException.class)
	public void instantiate_invalidKeyData() {
		new ProofKeys(Arrays.asList("PK.1. "));
	}

	private void verifyKey(ProofKey key, String dataStr, int version) {
		assertNotNull(key);
		assertEquals(dataStr, Base64.encode(key.getData()));
		assertEquals(version, key.getVersion());
	}

}
