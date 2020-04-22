package com.genexus.securityapicommons.encoders;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import com.genexus.securityapicommons.commons.SecurityAPIObject;
import com.genexus.securityapicommons.config.EncodingUtil;

/**
 * @author sgrampone
 *
 */
public class HexaEncoder extends SecurityAPIObject {

	/**
	 * Hexa class contstructor
	 */
	public HexaEncoder() {
		super();
	}

	/**
	 * @param plainText
	 *            String UTF-8 plain text
	 * @return String Hexa hexadecimal representation of plainText
	 */
	public String toHexa(String plainText) {
		EncodingUtil eu = new EncodingUtil();
		byte[] stringBytes = eu.getBytes(plainText);
		if(eu.hasError())
		{
			this.error = eu.getError();
			return "";
		}
		StringBuilder sb = new StringBuilder();
		for (byte b : stringBytes) {
			sb.append(String.format("%02X ", b));
		}
		String result = sb.toString().replaceAll("\\s", "");
		if (result == null || result.length() == 0) {
			this.error.setError("HE001", "Error encoding hexa");
			return "";
		}
		this.error.cleanError();
		return result;
	}

	/**
	 * @param stringHexa
	 *            String hexadecimal representation of a text
	 * @return String UTF-8 plain text from stringHexa
	 */
	public String fromHexa(String stringHexa) {

		byte[] resBytes = Hex.decode(stringHexa);
		EncodingUtil eu = new EncodingUtil();
		String result = eu.getString(resBytes);
		if(eu.hasError())
		{
			this.error = eu.getError();
			return "";
		}
		if (result == null || result.length() == 0) {
			this.error.setError("HE002", "Error decoding hexa");
			return "";
		}
		this.error.cleanError();
		return result;
	}

}
