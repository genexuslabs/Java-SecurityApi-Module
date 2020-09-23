package com.genexus.cryptography.symmetric;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.engines.HC128Engine;
import org.bouncycastle.crypto.engines.HC256Engine;
import org.bouncycastle.crypto.engines.ISAACEngine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.engines.VMPCEngine;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Base64;

import com.genexus.cryptography.commons.SymmectricStreamCipherObject;
import com.genexus.cryptography.symmetric.utils.SymmetricStreamAlgorithm;
import com.genexus.securityapicommons.config.EncodingUtil;
import com.genexus.securityapicommons.utils.SecurityUtils;

/**
 * @author sgrampone
 *
 */
public class SymmetricStreamCipher extends SymmectricStreamCipherObject {

	/**
	 * SymmetricStreamCipher class constructor
	 */
	public SymmetricStreamCipher() {
		super();
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/

	/**
	 * @param symmetricStreamAlgorithm String SymmetrcStreamAlgorithm enum,
	 *                                 algorithm name
	 * @param symmetricBlockMode       String SymmetricBlockMode enum, mode name
	 * @param key                      String Hexa key for the algorithm excecution
	 * @param IV                       String Hexa IV (nonce) for those algorithms
	 *                                 that uses, ignored if not
	 * @param plainText                String UTF-8 plain text to encrypt
	 * @return String Base64 encrypted text with the given algorithm and parameters
	 */
	public String doEncrypt(String symmetricStreamAlgorithm, String key, String IV, String plainText) {
		this.error.cleanError();
		SymmetricStreamAlgorithm algorithm = SymmetricStreamAlgorithm
				.getSymmetricStreamAlgorithm(symmetricStreamAlgorithm, this.error);

		if (this.error.existsError()) {
			return "";
		}

		StreamCipher engine = getCipherEngine(algorithm);
		if (this.error.existsError()) {
			return "";
		}

		byte[] keyBytes = SecurityUtils.getHexa(key, "SS007", this.error);
		byte[] ivBytes = SecurityUtils.getHexa(IV, "SS007", this.error);
		if (this.hasError()) {
			return "";
		}
		KeyParameter keyParam = new KeyParameter(keyBytes);
		if (SymmetricStreamAlgorithm.usesIV(algorithm, this.error)) {
			if (!this.error.existsError()) {
				ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, ivBytes);
				try {
					engine.init(true, keyParamWithIV);
				} catch (Exception e) {
					this.error.setError("SS008", e.getMessage());
					return "";
				}
			}
		} else {
			try {
				engine.init(true, keyParam);
			} catch (Exception e) {
				this.error.setError("SS009", e.getLocalizedMessage());
				return "";
			}
		}
		EncodingUtil eu = new EncodingUtil();
		byte[] input = eu.getBytes(plainText);
		if (eu.getError().existsError()) {
			this.error = eu.getError();
			return "";
		}
		byte[] output = new byte[input.length];
		engine.processBytes(input, 0, input.length, output, 0);
		String result = new String(Base64.encode(output));
		if (result == null || result.length() == 0) {
			this.error.setError("SS004", "Stream encryption exception");
			return "";
		}
		this.error.cleanError();
		return result;

	}

	/**
	 * @param symmetricStreamAlgorithm String SymmetrcStreamAlgorithm enum,
	 *                                 algorithm name
	 * @param symmetricBlockMode       String SymmetricBlockMode enum, mode name
	 * @param key                      String Hexa key for the algorithm excecution
	 * @param IV                       String Hexa IV (nonce) for those algorithms
	 *                                 that uses, ignored if not
	 * @param encryptedInput           String Base64 encrypted text with the given
	 *                                 algorithm and parameters
	 * @return String plain text UTF-8 with the given algorithm and parameters
	 */
	public String doDecrypt(String symmetricStreamAlgorithm, String key, String IV, String encryptedInput) {
		this.error.cleanError();
		SymmetricStreamAlgorithm algorithm = SymmetricStreamAlgorithm
				.getSymmetricStreamAlgorithm(symmetricStreamAlgorithm, this.error);

		if (this.error.existsError()) {
			return "";
		}

		StreamCipher engine = getCipherEngine(algorithm);
		if (this.error.existsError()) {
			return "";
		}
		byte[] keyBytes = SecurityUtils.getHexa(key, "SS010", this.error);
		byte[] ivBytes = SecurityUtils.getHexa(IV, "SS010", this.error);
		if (this.hasError()) {
			return "";
		}

		KeyParameter keyParam = new KeyParameter(keyBytes);
		if (SymmetricStreamAlgorithm.usesIV(algorithm, this.error)) {
			if (!this.error.existsError()) {
				ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, ivBytes);
				try {
					engine.init(false, keyParamWithIV);
				} catch (Exception e) {
					this.error.setError("SS011", e.getMessage());
					return "";
				}
			}
		} else {
			try {
				engine.init(false, keyParam);
			} catch (Exception e) {
				this.error.setError("SS012", e.getMessage());
				return "";
			}
		}

		byte[] input = Base64.decode(encryptedInput);
		byte[] output = new byte[input.length];
		engine.processBytes(input, 0, input.length, output, 0);
		if (output == null || output.length == 0) {
			this.error.setError("SS006", "Stream decryption exception");
		}
		EncodingUtil eu = new EncodingUtil();
		String result = eu.getString(output).trim();
		if (eu.getError().existsError()) {
			this.error = eu.getError();
			return "";
		}
		this.error.cleanError();
		return result;

	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

	/**
	 * @param algorithm SymmetrcStreamAlgorithm enum, algorithm name
	 * @return StreamCipher with the algorithm Stream Engine
	 */
	private StreamCipher getCipherEngine(SymmetricStreamAlgorithm algorithm) {
		// System.out.print("algorithm: "+ SymmetricStreamAlgorithm.valueOf(algorithm,
		// error));

		StreamCipher engine = null;

		switch (algorithm) {
		case RC4:
			engine = new RC4Engine();
			break;
		case HC128:
			engine = new HC128Engine();
			break;
		case HC256:
			engine = new HC256Engine();
			break;
		case SALSA20:
			engine = new Salsa20Engine();
			break;
		case CHACHA20:
			engine = new ChaChaEngine();
			break;
		case XSALSA20:
			engine = new XSalsa20Engine();
			break;
		case ISAAC:
			engine = new ISAACEngine();
			break;
		case VMPC:
			engine = new VMPCEngine();
			break;
		default:
			this.error.setError("SS005", "Cipher " + algorithm + " not recognised.");
			break;
		}
		return engine;

	}
}
