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

package client;

import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.client.HttpClient;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.Validator;
import model.Data;
import model.TransformResponse;
import model.exception.VirgilPythiaServiceException;
import model.request.TransformPasswordRequest;

import java.io.ByteArrayInputStream;
import java.net.MalformedURLException;
import java.net.URL;

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
public final class VirgilPythiaClient implements PythiaClient {

    private static final String BASE_URL = "https://api.virgilsecurity.com";

    private URL baseUrl;
    private HttpClient httpClient;

    public VirgilPythiaClient() {
        try {
            this.baseUrl = new URL(BASE_URL);
        } catch (MalformedURLException e) {
            e.printStackTrace();
            throw new IllegalArgumentException("VirgilPythiaClient -> 'BASE_URL' has wrong format");
        }
        httpClient = new HttpClient();
    }

    public VirgilPythiaClient(URL baseUrl) {
        Validator.checkNullAgrument(baseUrl, "VirgilPythiaClient -> 'baseUrl' should not be null");
        this.baseUrl = baseUrl;
    }

    @Override
    public TransformResponse transformPassword(Data salt,
                                               Data blindedPassword,
                                               Integer version,
                                               boolean includeProof,
                                               String token) throws VirgilPythiaServiceException {

        URL url = null;
        try {
            url = new URL(baseUrl, "/pythia/v1/password");
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        TransformPasswordRequest request = new TransformPasswordRequest(salt.asBase64String(),
                                                                        blindedPassword.asBase64String(),
                                                                        String.valueOf(version));

        if (includeProof)
            request.setIncludeProof(true);

        String body = ConvertionUtils.serializeToJson(request);

        try {
            return httpClient.execute(url,
                                      "GET",
                                      token,
                                      new ByteArrayInputStream(ConvertionUtils.toBytes(body)),
                                      TransformResponse.class);
        } catch (VirgilServiceException e) {
            e.printStackTrace();
            throw new VirgilPythiaServiceException("VirgilPythiaClient -> transformPassword was not successful");
        }
    }
}
