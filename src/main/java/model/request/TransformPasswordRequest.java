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

package model.request;

import com.google.gson.annotations.SerializedName;
import com.virgilsecurity.sdk.utils.Validator;

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
public class TransformPasswordRequest {
    private static final String INCLUDE_PROOF_TRUE = "true";

    @SerializedName("salt")
    private String salt;

    @SerializedName("blinded_password")
    private String blindedPassword;

    @SerializedName("version")
    private String version;

    @SerializedName("include_proof")
    private String includeProof;

    /**
     * For gson serialization
     */
    public TransformPasswordRequest() {
    }

    public TransformPasswordRequest(String salt, String blindedPassword, String version) {
        Validator.checkNullAgrument(salt, "TransformPasswordRequest -> 'salt' should not be null");
        Validator.checkEmptyAgrument(salt, "TransformPasswordRequest -> 'salt' should not be empty");
        this.salt = salt;

        Validator.checkNullAgrument(blindedPassword,
                                    "TransformPasswordRequest -> 'blindedPassword' should not be null");
        Validator.checkEmptyAgrument(blindedPassword,
                                     "TransformPasswordRequest -> 'blindedPassword' should not be empty");
        this.blindedPassword = blindedPassword;

        Validator.checkNullAgrument(version, "TransformPasswordRequest -> 'version' should not be null");
        Validator.checkEmptyAgrument(version, "TransformPasswordRequest -> 'version' should not be empty");
        this.version = version;
    }

    public TransformPasswordRequest(String salt, String blindedPassword, String version, boolean includeProof) {
        Validator.checkNullAgrument(salt, "TransformPasswordRequest -> 'salt' should not be null");
        Validator.checkEmptyAgrument(salt, "TransformPasswordRequest -> 'salt' should not be empty");
        this.salt = salt;

        Validator.checkNullAgrument(blindedPassword,
                                    "TransformPasswordRequest -> 'blindedPassword' should not be null");
        Validator.checkEmptyAgrument(blindedPassword,
                                     "TransformPasswordRequest -> 'blindedPassword' should not be empty");
        this.blindedPassword = blindedPassword;

        Validator.checkNullAgrument(version, "TransformPasswordRequest -> 'version' should not be null");
        Validator.checkEmptyAgrument(version, "TransformPasswordRequest -> 'version' should not be empty");
        this.version = version;

        if (includeProof)
            this.includeProof = INCLUDE_PROOF_TRUE;
    }

    public String getSalt() {
        return salt;
    }

    public String getBlindedPassword() {
        return blindedPassword;
    }

    public String getVersion() {
        return version;
    }

    public String getIncludeProof() {
        return includeProof;
    }

    public void setIncludeProof(boolean includeProof) {
        if (includeProof)
            this.includeProof = INCLUDE_PROOF_TRUE;
    }
}
