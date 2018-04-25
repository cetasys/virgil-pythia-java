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

package model;

import com.virgilsecurity.sdk.utils.Tuple;
import com.virgilsecurity.sdk.utils.Validator;
import model.exception.TransformationPublicKeyException;

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
public final class PythiaConfig {
    private final Tuple<Integer, Data> transformationPublicKey;
    private Tuple<Integer, Data> oldTransformationPublicKey;

    public PythiaConfig(Tuple<Integer, String> transformationPublicKey) {
        this(transformationPublicKey, null);
    }

    public PythiaConfig(Tuple<Integer, String> transformationPublicKey,
                        Tuple<Integer, String> oldTransformationPublicKey) {
        Validator.checkNullAgrument(transformationPublicKey,
                                    "PythiaConfig -> 'transformationPublicKey' should not be null");
        Validator.checkNullAgrument(transformationPublicKey.getLeft(),
                                    "PythiaConfig -> 'transformationPublicKey.getLeft()' should not be null");
        Validator.checkNullAgrument(transformationPublicKey.getRight(),
                                    "PythiaConfig -> 'transformationPublicKey.getRight()' should not be null");

        this.transformationPublicKey = new Tuple<>(transformationPublicKey.getLeft(),
                                                   Data.fromBase64String(transformationPublicKey.getRight()));

        if (oldTransformationPublicKey != null) {
            Validator.checkNullAgrument(oldTransformationPublicKey.getLeft(),
                                        "PythiaConfig -> 'oldTransformationPublicKey.getLeft()' should not be null");
            Validator.checkNullAgrument(oldTransformationPublicKey.getRight(),
                                        "PythiaConfig -> 'oldTransformationPublicKey.getRight()' should not be null");

            this.oldTransformationPublicKey = new Tuple<>(oldTransformationPublicKey.getLeft(),
                                                          Data.fromBase64String(oldTransformationPublicKey.getRight()));
        }
    }

    public Data transformationPublicKey(Integer version) {
        if (version.equals(transformationPublicKey.getLeft()))
            return transformationPublicKey.getRight();

        if (version.equals(oldTransformationPublicKey.getLeft()))
            return oldTransformationPublicKey.getRight();

        throw new TransformationPublicKeyException();
    }

    public Tuple<Integer, Data> getTransformationPublicKey() {
        return transformationPublicKey;
    }

    public Tuple<Integer, Data> getOldTransformationPublicKey() {
        return oldTransformationPublicKey;
    }
}
