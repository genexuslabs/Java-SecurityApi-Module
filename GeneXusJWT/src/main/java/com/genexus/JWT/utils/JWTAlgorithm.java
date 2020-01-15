package com.genexus.JWT.utils;

import com.auth0.jwt.algorithms.Algorithm;
import com.genexus.securityapicommons.commons.Error;
import com.genexus.securityapicommons.keys.CertificateX509;
import com.genexus.securityapicommons.keys.PrivateKeyManager;

public enum JWTAlgorithm {
	HS256, HS512, RS256, RS512,;

	public static String valueOf(JWTAlgorithm jWTAlgorithm, Error error) {
		switch (jWTAlgorithm) {
		case HS256:
			return "HS256";
		case HS512:
			return "HS512";
		case RS256:
			return "RS256";
		case RS512:
			return "RS512";
		default:
			error.setError("JA001", "Unrecognized algorithm");
			return "Unrecognized algorithm";
		}
	}

	public static JWTAlgorithm getJWTAlgorithm(String jWTAlgorithm, Error error) {
		switch (jWTAlgorithm) {
		case "HS256":
			return JWTAlgorithm.HS256;
		case "HS512":
			return JWTAlgorithm.HS512;
		case "RS256":
			return JWTAlgorithm.RS256;
		case "RS512":
			return JWTAlgorithm.RS512;
		default:
			error.setError("JA002", "Unrecognized algorithm");
			return null;
		}
	}

	public static boolean isPrivate(JWTAlgorithm jWTAlgorithm) {
		switch (jWTAlgorithm) {
		case RS256:
		case RS512:
			return true;
		default:
			return false;
		}
	}

	public static Algorithm getSymmetricAlgorithm(JWTAlgorithm algorithm, byte[] secret, Error error) {
		if (isPrivate(algorithm)) {
			error.setError("JA003", "It is not a symmetric algorithm name");
			return null;
		} else {
			switch (algorithm) {
			case HS256:
				return Algorithm.HMAC256(secret);
			case HS512:
				return Algorithm.HMAC512(secret);
			default:
				error.setError("JA004", "Unknown symmetric algorithm");
				return null;
			}
		}

	}

	public static Algorithm getAsymmetricAlgorithm(JWTAlgorithm algorithm, PrivateKeyManager key, CertificateX509 cert, Error error) {
		if (!isPrivate(algorithm)) {
			error.setError("JA005", "It is not an asymmetric algorithm name");
			return null;
		} else {
			switch (algorithm) {
			case RS256:
				try {
					return Algorithm.RSA256(cert.getRSAPublicKey(), key.getRSAPrivateKeyJWT());
				} catch (Exception e) {
					error.setError("JA007", e.getMessage());
					return null;
				}
			case RS512:
				try {
					return Algorithm.RSA512(cert.getRSAPublicKey(), key.getRSAPrivateKeyJWT());
				} catch (Exception e) {
					error.setError("JA008", e.getMessage());
					return null;
				}
			default:
				error.setError("JA006", "Unknown asymmetric algorithm");
				return null;
			}
		}

	}
}
