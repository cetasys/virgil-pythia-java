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

package auth;

import client.PythiaClient;
import com.virgilsecurity.crypto.VirgilPythia;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.TokenContext;
import com.virgilsecurity.sdk.jwt.contract.AccessToken;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.Tuple;
import com.virgilsecurity.sdk.utils.Validator;
import model.Data;
import model.PythiaConfig;
import model.PythiaUser;
import model.TransformResponse;
import model.exception.TransformVerificationException;
import model.exception.VirgilPythiaServiceException;

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
public final class VirgilPythiaPasswordProtection implements PythiaPasswordProtection {
    private static final String OPERATION_GET = "get";

    private final PythiaConfig config;
    private final PythiaClient pythiaClient;
    private final VirgilPythia pythiaCrypto;
    private final AccessTokenProvider accessTokenProvider;

    public VirgilPythiaPasswordProtection(PythiaConfig config,
                                          PythiaClient pythiaClient,
                                          VirgilPythia pythiaCrypto,
                                          AccessTokenProvider accessTokenProvider) {
        Validator.checkNullAgrument(config,
                                    "VirgilPythiaPasswordProtection -> 'config' should not be null");
        Validator.checkNullAgrument(pythiaClient,
                                    "VirgilPythiaPasswordProtection -> 'pythiaClient' should not be null");
        Validator.checkNullAgrument(pythiaCrypto,
                                    "VirgilPythiaPasswordProtection -> 'pythiaCrypto' should not be null");
        Validator.checkNullAgrument(accessTokenProvider,
                                    "VirgilPythiaPasswordProtection -> 'accessTokenProvider' should not be null");

        this.config = config;
        this.pythiaClient = pythiaClient;
        this.pythiaCrypto = pythiaCrypto;
        this.accessTokenProvider = accessTokenProvider;
    }

    @Override public PythiaUser register(String password)
            throws CryptoException, TransformVerificationException, VirgilPythiaServiceException {

        Tuple<Data, Data> blinded = pythiaCrypto.blind(password);
        Data blindedPassword = blinded.getLeft();
        Data blindingSecret = blinded.getRight();
        Data salt = pythiaCrypto.generateSalt();

        TokenContext tokenContext = new TokenContext(OPERATION_GET, false);
        AccessToken accessToken = accessTokenProvider.getToken(tokenContext);
        Tuple<Integer, Data> latestTransformationPublicKey = config.getTransformationPublicKey();
        TransformResponse transformResponse = pythiaClient.transformPassword(salt,
                                                                             blindedPassword,
                                                                             latestTransformationPublicKey.getLeft(),
                                                                             true,
                                                                             accessToken.stringRepresentation());

        boolean isTransformVerified = pythiaCrypto.verify(transformResponse.getTransformedPassword(),
                                                          blindedPassword,
                                                          salt,
                                                          latestTransformationPublicKey.getRight(),
                                                          transformResponse.getProof().getC(),
                                                          transformResponse.getProof().getU());

        if (!isTransformVerified)
            throw new TransformVerificationException();

        Data deblindedPassword = pythiaCrypto.deblind(transformResponse.getTransformedPassword(),
                                                      blindingSecret);

        return new PythiaUser(salt, deblindedPassword, latestTransformationPublicKey.getLeft());
    }

    @Override
    public PythiaUser rotateSecret(Integer newVersion, String updateToken, PythiaUser pythiaUser) {
        Data updateTokenData = Data.fromBase64String(updateToken);
        Data newDeblindedPassword = pythiaCrypto.updateDeblindedWithToken(pythiaUser.getDeblindedPassword(),
                                                                          updateTokenData);

        return new PythiaUser(pythiaUser.getSalt(), newDeblindedPassword, newVersion);
    }

    @Override
    public boolean authenticate(String password,
                                PythiaUser pythiaUser,
                                boolean proof)
            throws CryptoException, TransformVerificationException, VirgilPythiaServiceException {

        TokenContext tokenContext = new TokenContext(OPERATION_GET, false);
        AccessToken accessToken = accessTokenProvider.getToken(tokenContext);
        Tuple<Data, Data> blinded = pythiaCrypto.blind(password);
        Data blindedPassword = blinded.getLeft();
        Data blindingSecret = blinded.getRight();
        Data transformationPublicKey = config.transformationPublicKey(pythiaUser.getVersion());

        TransformResponse transformResponse = pythiaClient.transformPassword(pythiaUser.getSalt(),
                                                                             blindedPassword,
                                                                             pythiaUser.getVersion(),
                                                                             true,
                                                                             accessToken.stringRepresentation());

        boolean isTransformVerified = pythiaCrypto.verify(transformResponse.getTransformedPassword(),
                                                          blindedPassword,
                                                          pythiaUser.getSalt(),
                                                          transformationPublicKey,
                                                          transformResponse.getProof().getC(),
                                                          transformResponse.getProof().getU());

        if (!isTransformVerified)
            throw new TransformVerificationException();

        Data deblindedPassword = pythiaCrypto.deblind(transformResponse.getTransformedPassword(),
                                                      blindingSecret);

        return deblindedPassword.equals(pythiaUser.getDeblindedPassword()); // FIXME: See if if correct
    }
}
