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

import client.PythiaClient;
import com.virgilsecurity.crypto.VirgilPythia;
import com.virgilsecurity.crypto.VirgilPythiaTransformResult;
import model.Data;
import model.TransformResponse;

import java.util.Random;

/**
 * .._  _
 * .| || | _
 * -| || || |   Created by:
 * .| || || |-  Danylo Oliinyk
 * ..\_  || |   on
 * ....|  _/    4/18/18
 * ...-| | \    at Virgil Security
 * ....|_|-
 */
public class MockPythiaClient implements PythiaClient {

    @Override
    public TransformResponse transformPassword(Data salt,
                                               Data blindedPassword,
                                               Integer version,
                                               boolean includeProof,
                                               String token) {
        Random random = new Random();
        int lenght = 32;
        byte[] transformationKeyId = new byte[lenght];
        random.nextBytes(transformationKeyId);
        byte[] tweak = new byte[lenght];
        random.nextBytes(tweak);
        byte[] pythiaSecret = new byte[lenght];
        random.nextBytes(pythiaSecret);
        byte[] pythiaScopeSecret = new byte[lenght];
        random.nextBytes(pythiaScopeSecret);

        VirgilPythia pythia = new VirgilPythia();
        VirgilPythiaTransformResult transformResult =
                pythia.transform(blindedPassword.asBytes(),
                                 transformationKeyId,
                                 tweak,
                                 pythiaSecret,
                                 pythiaScopeSecret);

        return new TransformResponse(Data.fromBytes(transformResult.transformedPassword()));
    }
}
