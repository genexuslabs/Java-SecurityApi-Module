package com.genexus.cryptography.symmetric.utils;

import com.genexus.securityapicommons.commons.Error;

/**
 * @author sgrampone
 *
 */
public enum SymmetricStreamAlgorithm {
	RC4, HC128, HC256, CHACHA20, SALSA20, XSALSA20, ISAAC, VMPC,;

	/**
	 * Mapping between String name and SymmetricStreamAlgorithm enum representation
	 * 
	 * @param symmetricStreamAlgorithm
	 *            String
	 * @param error
	 *            Error type for error management
	 * @return SymmetricStreamAlgorithm enum representation
	 */
	public static SymmetricStreamAlgorithm getSymmetricStreamAlgorithm(String symmetricStreamAlgorithm, Error error) {
		switch (symmetricStreamAlgorithm) {
		case "RC4":
			return SymmetricStreamAlgorithm.RC4;
		case "HC128":
			return SymmetricStreamAlgorithm.HC128;
		case "HC256":
			return SymmetricStreamAlgorithm.HC256;
		case "CHACHA20":
			return SymmetricStreamAlgorithm.CHACHA20;
		case "SALSA20":
			return SymmetricStreamAlgorithm.SALSA20;
		case "XSALSA20":
			return SymmetricStreamAlgorithm.XSALSA20;
		case "ISAAC":
			return SymmetricStreamAlgorithm.ISAAC;
		case "VMPC":
			return SymmetricStreamAlgorithm.VMPC;
		default:
			error.setError("SS001", "Unrecognized SymmetricStreamAlgorithm");
			return null;
		}
	}

	/**
	 * @param symmetrcStreamAlgorithm
	 *            SymmetrcStreamAlgorithm enum, algorithm name
	 * @param error
	 *            Error type for error management
	 * @return String SymmetrcStreamAlgorithm name value
	 */
	public static String valueOf(SymmetricStreamAlgorithm symmetrcStreamAlgorithm, Error error) {
		switch (symmetrcStreamAlgorithm) {
		case RC4:
			return "RC4";
		case HC128:
			return "HC128";
		case HC256:
			return "HC256";
		case CHACHA20:
			return "CHACHA20";
		case SALSA20:
			return "SALSA20";
		case XSALSA20:
			return "XSALSA20";
		case ISAAC:
			return "ISAAC";
		case VMPC:
			return "VMPC";
		default:
			error.setError("SS002", "Unrecognized SymmetricStreamAlgorithm");
			return "Unrecognized algorithm";
		}
	}

	/**
	 * @param algorithm
	 *            SymmetrcStreamAlgorithm enum, algorithm name
	 * @param error
	 *            Error type for error management
	 * @return array int with fixed length 3 with key, if array[0]=0 is range, else
	 *         fixed values
	 */
	protected static int[] getKeySize(SymmetricStreamAlgorithm algorithm, Error error) {
		int[] keySize = new int[3];
		switch (algorithm) {
		case RC4:
			keySize[0] = 0;
			keySize[1] = 40;
			keySize[2] = 2048;
			break;
		case HC128:
			keySize[0] = 1;
			keySize[1] = 128;
			break;
		case HC256:
		case XSALSA20:
			keySize[0] = 1;
			keySize[1] = 256;
			break;
		case CHACHA20:
		case SALSA20:
			keySize[0] = 1;
			keySize[1] = 128;
			keySize[2] = 256;
			break;
		case ISAAC:
			keySize[0] = 0;
			keySize[1] = 32;
			keySize[2] = 8192;
			break;
		case VMPC:
			keySize[0] = 0;
			keySize[1] = 8;
			keySize[2] = 6144;
			break;
		default:
			error.setError("SS003", "Unrecognized SymmetricStreamAlgorithm");
			break;
		}
		return keySize;
	}

	/**
	 * @param algorithm
	 *            SymmetricStreamAlgorithm enum
	 * @param error
	 *            Error type for error management
	 * @return true if the algorithm uses an IV or nonce, false if it do not
	 */
	public static boolean usesIV(SymmetricStreamAlgorithm algorithm, Error error) {
		switch (algorithm) {
		case RC4:
		case HC128:
		case ISAAC:
			return false;
		case HC256:
		case SALSA20:
		case CHACHA20:
		case XSALSA20:
		case VMPC:
			return true;
		default:
			error.setError("SS007", "Unrecognized SymmetricStreamAlgorithm");
			return true;
		}

	}
}
