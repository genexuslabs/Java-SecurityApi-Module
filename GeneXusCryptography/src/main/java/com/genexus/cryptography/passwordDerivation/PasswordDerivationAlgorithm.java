package com.genexus.cryptography.passwordDerivation;

import com.genexus.securityapicommons.commons.Error;

/**
 * @author sgrampone
 *
 */
public enum PasswordDerivationAlgorithm {
	SCrypt, Bcrypt,;

	/**
	 * Mapping between String name and PasswordDerivationAlgorithm enum
	 * representation
	 * 
	 * @param passwordDerivationAlgorithm
	 *            String
	 * @param error
	 *            Error type for error management
	 * @return PasswordDerivationAlgorithm enum representation
	 */
	public static PasswordDerivationAlgorithm getPasswordDerivationAlgorithm(String passwordDerivationAlgorithm,
			Error error) {
		switch (passwordDerivationAlgorithm) {
		case "SCrypt":
			return PasswordDerivationAlgorithm.SCrypt;
		case "Bcrypt":
			return PasswordDerivationAlgorithm.Bcrypt;
		default:
			error.setError("PD001", "Unrecognized PasswordDerivationAlgorithm");
			return null;
		}
	}

	/**
	 * @param passwordDerivationAlgorithm
	 *            PasswordDerivationAlgorithm enum, algorithm name
	 * @param error
	 *            Error type for error management
	 * @return PasswordDerivationAlgorithm value in String
	 */
	public static String valueOf(PasswordDerivationAlgorithm passwordDerivationAlgorithm, Error error) {
		switch (passwordDerivationAlgorithm) {
		case SCrypt:
			return "SCrypt";
		case Bcrypt:
			return "Bcrypt";
		default:
			error.setError("PD002", "Unrecognized PasswordDerivationAlgorithm");
			return "Unrecognized algorithm";
		}
	}

}
