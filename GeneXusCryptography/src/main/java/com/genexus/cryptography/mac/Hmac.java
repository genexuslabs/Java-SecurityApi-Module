package com.genexus.cryptography.mac;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import com.genexus.cryptography.commons.HmacObject;
import com.genexus.cryptography.hash.Hashing;
import com.genexus.cryptography.hash.utils.HashAlgorithm;
import com.genexus.securityapicommons.config.EncodingUtil;
import com.genexus.securityapicommons.utils.SecurityUtils;

public class Hmac extends HmacObject {

	public Hmac() {
		super();
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/
	@Override
	public String calculate(String plainText, String password, String algorithm) {
		byte[] pass = SecurityUtils.getHexa(password, "HS002", this.error);
		if (this.hasError()) {
			return "";
		}
		EncodingUtil eu = new EncodingUtil();
		byte[] inputBytes = eu.getBytes(plainText);
		if (this.hasError()) {
			return "";
		}
		Hashing hash = new Hashing();
		HashAlgorithm alg = HashAlgorithm.getHashAlgorithm(algorithm, this.error);
		if (this.hasError()) {
			return "";
		}
		Digest digest = hash.createHash(alg);
		HMac engine = new HMac(digest);
		try {
			engine.init(new KeyParameter(pass));
		} catch (Exception e) {
			this.error.setError("HS003", e.getMessage());
			return "";
		}
		byte[] resBytes = new byte[engine.getMacSize()];
		engine.update(inputBytes, 0, inputBytes.length);
		engine.doFinal(resBytes, 0);

		String result = toHexaString(resBytes);
		if (!this.error.existsError()) {
			return result;
		}
		return "";

	}

	@Override
	public boolean verify(String plainText, String password, String mac, String algorithm) {
		String res = calculate(plainText, password, algorithm);
		return SecurityUtils.compareStrings(res, mac);
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

	/**
	 * @param digest byte array
	 * @return String Hexa respresentation of the byte array digest
	 */
	private String toHexaString(byte[] digest) {

		if (this.error.existsError()) {
			return "";
		}

		StringBuilder sb = new StringBuilder();
		for (byte b : digest) {
			sb.append(String.format("%02X ", b));
		}
		String result = sb.toString().replaceAll("\\s", "");
		if (result == null || result.length() == 0) {
			this.error.setError("HS001", "Error encoding hexa");
			return "";
		}
		return result.trim();

	}

}
