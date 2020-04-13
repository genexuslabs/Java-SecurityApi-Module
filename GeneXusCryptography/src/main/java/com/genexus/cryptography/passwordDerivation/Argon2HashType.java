package com.genexus.cryptography.passwordDerivation;

import org.bouncycastle.crypto.params.Argon2Parameters;

import com.genexus.securityapicommons.commons.Error;

public enum Argon2HashType {
	ARGON2_d, ARGON2_i, ARGON2_id;

	public static Argon2HashType getArgon2HashType(String argon2HashType, Error error) {
		switch (argon2HashType) {
		case "ARGON2_d":
			return Argon2HashType.ARGON2_d;
		case "ARGON2_i":
			return Argon2HashType.ARGON2_i;
		case "ARGON2_id":
			return Argon2HashType.ARGON2_id;
		default:
			error.setError("A2001", "Unrecognized Arggon2HashType");
			return null;
		}

	}

	public static String valueOf(Argon2HashType argon2HashType, Error error) {
		switch (argon2HashType) {
		case ARGON2_d:
			return "ARGON2_d";
		case ARGON2_i:
			return "ARGON2_i";
		case ARGON2_id:
			return "ARGON2_id";
		default:
			error.setError("A2002", "Unrecognized Arggon2HashType");
			return "";
		}
	}

	public static int getArgon2Parameter(Argon2HashType argon2HashType, Error error) {
		switch (argon2HashType) {
		case ARGON2_d:
			return Argon2Parameters.ARGON2_d;
		case ARGON2_i:
			return Argon2Parameters.ARGON2_i;
		case ARGON2_id:
			return Argon2Parameters.ARGON2_id;
		default:
			error.setError("A2003", "Unrecognized Arggon2HashType");
			return 0;
		}
	}
}
