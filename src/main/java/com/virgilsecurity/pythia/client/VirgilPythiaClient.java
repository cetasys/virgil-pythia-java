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

package com.virgilsecurity.pythia.client;

import java.io.BufferedInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.virgilsecurity.pythia.model.TransformResponse;
import com.virgilsecurity.pythia.model.exception.VirgilPythiaServiceException;
import com.virgilsecurity.pythia.model.request.TransformPasswordRequest;
import com.virgilsecurity.sdk.common.ErrorResponse;
import com.virgilsecurity.sdk.common.HttpError;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;
import com.virgilsecurity.sdk.utils.Validator;

/**
 * {@link PythiaClient} implementation.
 * 
 * @author Andrii Iakovenko
 *
 */
public final class VirgilPythiaClient implements PythiaClient {

    private static final Logger LOGGER = Logger.getLogger(VirgilPythiaClient.class.getName());
    private static final String BASE_URL = "https://api.virgilsecurity.com";

    private URL baseUrl;

    /**
     * Create a new instance of {@link VirgilPythiaClient}.
     *
     */
    public VirgilPythiaClient() {
        this(BASE_URL);
    }

    /**
     * Create a new instance of {@link VirgilPythiaClient}.
     *
     * @param baseUrl
     *            the service url to fire requests to.
     */
    public VirgilPythiaClient(String baseUrl) {
        Validator.checkNullAgrument(baseUrl, "VirgilPythiaClient -> 'baseUrl' should not be null");
        try {
            this.baseUrl = new URL(baseUrl);
        } catch (MalformedURLException e) {
            LOGGER.log(Level.SEVERE, "Base URL has wrong format", e);
            throw new IllegalArgumentException("VirgilPythiaClient -> 'baseUrl' has wrong format");
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.virgilsecurity.pythia.client.PythiaClient#transformPassword(byte[],
     * byte[], java.lang.Integer, boolean, java.lang.String)
     */
    @Override
    public TransformResponse transformPassword(byte[] salt, byte[] blindedPassword, Integer version,
            boolean includeProof, String token) throws VirgilPythiaServiceException {

        TransformPasswordRequest request = new TransformPasswordRequest(salt, blindedPassword, version, includeProof);
        String body = ConvertionUtils.serializeToJson(request);

        try {
            // Create connection
            URL url = new URL(baseUrl, "/pythia/v1/password");
            HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();

            try {
                urlConnection.setRequestMethod("POST");
                urlConnection.setDoOutput(true);
                urlConnection.setUseCaches(false);
                urlConnection.setRequestProperty("Content-Type", "application/json; charset=utf-8");

                // Set authorization token
                if (!StringUtils.isBlank(token)) {
                    urlConnection.setRequestProperty("Authorization", "Virgil " + token);
                } else {
                    LOGGER.warning("Provided token is blank");
                }

                // Send payload
                urlConnection.getOutputStream().write(ConvertionUtils.toBytes(body));

                if (urlConnection.getResponseCode() >= HttpURLConnection.HTTP_BAD_REQUEST) {
                    LOGGER.warning("Http error occurred...");
                    HttpError httpError = new HttpError(urlConnection.getResponseCode(),
                            urlConnection.getResponseMessage());

                    // Get error code from request
                    try (InputStream in = new BufferedInputStream(urlConnection.getErrorStream())) {
                        LOGGER.fine("Trying to get error info...");
                        String errBody = ConvertionUtils.toString(in);
                        if (StringUtils.isBlank(errBody)) {
                            throw new VirgilPythiaServiceException(httpError);
                        } else {
                            ErrorResponse error = ConvertionUtils.getGson().fromJson(errBody, ErrorResponse.class);
                            throw new VirgilPythiaServiceException(error.getCode(), error.getMessage(), httpError);
                        }
                    }
                } else {
                    LOGGER.fine("Extracting response body...");
                    try (InputStream instream = new BufferedInputStream(urlConnection.getInputStream())) {
                        String responseBody = ConvertionUtils.toString(instream);
                        TransformResponse transformResponse = ConvertionUtils.getGson().fromJson(responseBody,
                                TransformResponse.class);
                        return transformResponse;
                    }
                }
            } finally {
                LOGGER.fine("Disconnecting...");
                urlConnection.disconnect();
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Some service issue occurred during request executing", e);
            throw new VirgilPythiaServiceException("VirgilPythiaClient -> transformPassword was not successful");
        }
    }
}
