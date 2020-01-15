package com.genexus.cryptography.asymmetric.utils;

import com.genexus.securityapicommons.commons.Error;

/**
 * @author sgrampone
 *
 */
public enum AsymmetricSigningAlgorithm {

	RSA, ECDSA,;

	/**
	 * Mapping between String name and AsymmetricSigningAlgorithm enum
	 * representation
	 * 
	 * @param asymmetricSigningAlgorithm
	 *            String
	 * @param error
	 *            Error type for error management
	 * @return AsymmetricSigningAlgorithm enum representation
	 */
	public static AsymmetricSigningAlgorithm getAsymmetricSigningAlgorithm(String asymmetricSigningAlgorithm,
			Error error) {
		switch (asymmetricSigningAlgorithm) {
		case "RSA":
			return AsymmetricSigningAlgorithm.RSA;
		case "ECDSA":
			return AsymmetricSigningAlgorithm.ECDSA;
		default:
			error.setError("AE005", "Unrecognized AsymmetricSigningAlgorithm");
			return null;
		}
	}

	/**
	 * @param asymmetricSigningAlgorithm
	 *            AsymmetricSigningAlgorithm enum, algorithm name
	 * @param error
	 *            Error type for error management
	 * @return String value of the algorithm
	 */
	public static String valueOf(AsymmetricSigningAlgorithm asymmetricSigningAlgorithm, Error error) {
		switch (asymmetricSigningAlgorithm) {
		case RSA:
			return "RSA";
		case ECDSA:
			return "ECDSA";
		default:
			error.setError("AE006", "Unrecognized AsymmetricSigningAlgorithm");
			return "";
		}
	}
}
