package com.genexus.securityapicommons.encoders;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import com.genexus.securityapicommons.commons.SecurityAPIObject;
import com.genexus.securityapicommons.config.EncodingUtil;

/**
 * @author sgrampone
 *
 */
public class Base64Encoder extends SecurityAPIObject {

	/**
	 * Base64Encoder class constructor
	 */
	public Base64Encoder() {
		super();
	}

	/**
	 * @param text
	 *            String UTF-8 plain text to encode
	 * @return Base64 String text encoded
	 */
	public String toBase64(String text) {
		byte[] textBytes = new EncodingUtil().getBytes(text);
		String result = new String(Base64.encode(textBytes));
		if (result == null || result.length() == 0) {
			this.error.setError("B64001", "Error encoding base64");
			return "";
		}
		this.error.cleanError();
		return result;
	}

	/**
	 * @param base64Text
	 *            String Base64 encoded
	 * @return String UTF-8 plain text from Base64
	 */
	public String toPlainText(String base64Text) {
		byte[] bytes = Base64.decode(base64Text);

		String result = new EncodingUtil().getString(bytes);
		if (result == null || result.length() == 0) {
			this.error.setError("B64002", "Error decoding base64");
			return "";
		}
		this.error.cleanError();
		return result;
	}

	/**
	 * @param base64Text
	 *            String Base64 encoded
	 * @return String Hexa representation of base64Text
	 */
	public String toStringHexa(String base64Text) {
		byte[] bytes = Base64.decode(base64Text);
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02X ", b));
		}
		String result = sb.toString().replaceAll("\\s", "");
		if (result == null || result.length() == 0) {
			this.error.setError("B64003", "Error decoding base64 to hexa");
			return "";
		}
		this.error.cleanError();
		return result;
	}

	/**
	 * @param stringHexa
	 *            String Hexa
	 * @return String Base64 encoded of stringHexa
	 */
	public String fromStringHexaToBase64(String stringHexa) {
		byte[] stringBytes = Hex.decode(stringHexa);
		String result = new String(Base64.encode(stringBytes));
		if (result == null || result.length() == 0) {
			this.error.setError("B64004", "Error encoding base64 from hexa");
			return "";
		}
		this.error.cleanError();
		return result;
	}
}
