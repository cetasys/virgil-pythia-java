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

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import javax.xml.bind.DatatypeConverter;

/**
 * This class could store JSON sample data and provide common operations with a sample.
 * 
 * @author Andrii Iakovenko
 *
 */
public class SampleDataHolder {

  private JsonObject sampleJson;

  /**
   * Create a new instance of {@link SampleDataHolder}.
   *
   * @param path
   *          the path to the sample resource.
   */
  public SampleDataHolder(String path) {
    sampleJson = (JsonObject) new JsonParser()
        .parse(new InputStreamReader(this.getClass().getClassLoader().getResourceAsStream(path)));
  }

  /**
   * Get sample data as a string.
   * 
   * @param key
   *          the key.
   * @return a value by key.
   */
  public String get(String key) {
    return this.sampleJson.get(key).getAsString();
  }

  /**
   * Get sample data as an array.
   * 
   * @param key
   *          the key.
   * @return an array by key.
   */
  public JsonArray getArray(String key) {
    return this.sampleJson.get(key).getAsJsonArray();
  }

  /**
   * Get sample data as byte array.
   * 
   * @param key
   *          the key.
   * @return byte array by key.
   */
  public byte[] getBytes(String key) {
    return this.sampleJson.get(key).getAsString().getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Get sample data as byte array decoded from HEX-string.
   * 
   * @param key
   *          the key.
   * @return byte array.
   */
  public byte[] getHexBytes(String key) {
    return DatatypeConverter.parseHexBinary(this.sampleJson.get(key).getAsString());
  }

}
