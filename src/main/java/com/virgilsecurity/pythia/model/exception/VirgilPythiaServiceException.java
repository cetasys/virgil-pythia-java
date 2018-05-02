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

package com.virgilsecurity.pythia.model.exception;

import com.virgilsecurity.sdk.common.HttpError;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.utils.StringUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class VirgilPythiaServiceException extends VirgilException {

	private static final long serialVersionUID = -291746913484051059L;

	private int error;
	private String message;
	private HttpError httpError;

	/**
	 * Create a new instance of {@link VirgilPythiaServiceException}.
	 *
	 * @param message
	 */
	public VirgilPythiaServiceException(String message) {
		this.message = message;
	}

	/**
	 * Create a new instance of {@link VirgilPythiaServiceException}.
	 *
	 * @param httpError
	 */
	public VirgilPythiaServiceException(HttpError httpError) {
		this.httpError = httpError;
	}

	/**
	 * Create a new instance of {@link VirgilPythiaServiceException}.
	 *
	 * @param error
	 * @param message
	 * @param httpError
	 */
	public VirgilPythiaServiceException(int error, String message, HttpError httpError) {
		this.error = error;
		this.message = message;
		this.httpError = httpError;
	}

	/**
	 * @return the serialversionuid
	 */
	public static long getSerialversionuid() {
		return serialVersionUID;
	}

	/**
	 * @return the error
	 */
	public int getError() {
		return error;
	}

	/**
	 * @return the message
	 */
	public String getMessage() {
		StringBuilder sb = new StringBuilder("\n");
		if (httpError != null) {
            sb.append("Http response: ").append(httpError.getCode());
            if (!StringUtils.isBlank(httpError.getMessage())) {
                sb.append(":").append(httpError.getMessage());
            }
            sb.append("\n");
        }
		sb.append("Server response:").append(error).append(":").append(message);
		return sb.toString();
	}

	/**
	 * @return the httpError
	 */
	public HttpError getHttpError() {
		return httpError;
	}

}
