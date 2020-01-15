package com.genexus.JWT.claims;

import java.text.SimpleDateFormat;
import java.util.Date;

import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.interfaces.Verification;
import com.genexus.securityapicommons.commons.Error;

public enum RegisteredClaim {
	iss, exp, sub, aud, nbf, iat, jti,;

	public static String valueOf(RegisteredClaim registeredClaim, Error error) {
		switch (registeredClaim) {
		case iss:
			return "iss";
		case exp:
			return "exp";
		case sub:
			return "sub";
		case aud:
			return "aud";
		case nbf:
			return "nbf";
		case iat:
			return "iat";
		case jti:
			return "jti";
		default:
			error.setError("RC001", "Unknown registered Claim");
			return "Unknown registered claim";

		}
	}

	public static RegisteredClaim getRegisteredClaim(String registeredClaim, Error error) {
		switch (registeredClaim) {
		case "iss":
			return RegisteredClaim.iss;
		case "exp":
			return RegisteredClaim.exp;
		case "sub":
			return RegisteredClaim.sub;
		case "aud":
			return RegisteredClaim.aud;
		case "nbf":
			return RegisteredClaim.nbf;
		case "iat":
			return RegisteredClaim.iat;
		case "jti":
			return RegisteredClaim.jti;
		default:
			error.setError("RC002", "Unknown registered Claim");
			return null;
		}
	}

	public static boolean exists(String value) {
		switch (value) {
		case "iss":
		case "exp":
		case "sub":
		case "aud":
		case "nbf":
		case "iat":
		case "jti":
			return true;
		default:
			return false;
		}
	}

	public static boolean isTimeValidatingClaim(String claimKey) {
		switch (claimKey) {
		case "iat":
		case "exp":
		case "nbf":
			return true;
		default:
			return false;
		}
	}

	public static Verification getVerificationWithClaim(String registeredClaimKey, String registeredClaimValue,
			long registeredClaimCustomTime, Verification verification, Error error) {
		RegisteredClaim regClaim = getRegisteredClaim(registeredClaimKey, error);
		if (error.existsError()) {
			return null;
		} else {
			return getVerificationWithClaim(regClaim, registeredClaimValue, registeredClaimCustomTime, verification,
					error);
		}
	}

	public static Verification getVerificationWithClaim(RegisteredClaim registeredClaimKey, String registeredClaimValue,
			long registeredClaimCustomTime, Verification verification, Error error) {
		switch (registeredClaimKey) {
		case iss:
			verification.withIssuer(registeredClaimValue);
			break;
		case exp:
			if (registeredClaimCustomTime != 0) {
				verification.acceptExpiresAt(registeredClaimCustomTime);
			}
			break;
		case sub:
			verification.withSubject(registeredClaimValue);
			break;
		case aud:
			verification.withAudience(registeredClaimValue);
			break;
		case nbf:
			if (registeredClaimCustomTime != 0) {
				verification.acceptNotBefore(registeredClaimCustomTime);
			}
			break;
		case iat:
			if (registeredClaimCustomTime != 0) {
				verification.acceptIssuedAt(registeredClaimCustomTime);
			}
			break;
		case jti:
			verification.withJWTId(registeredClaimValue);
			break;
		default:
			error.setError("RC005", "Unknown registered claim");
			return null;
		}
		return verification;
	}

	public static Builder getBuilderWithClaim(String registeredClaimKey, String registeredClaimValue,
			Builder tokenBuilder, Error error) {
		RegisteredClaim regClaim = getRegisteredClaim(registeredClaimKey, error);
		if (error.existsError()) {
			return null;
		} else {
			return getBuilderWithClaim(regClaim, registeredClaimValue, tokenBuilder, error);
		}
	}

	public static Builder getBuilderWithClaim(RegisteredClaim registeredClaimKey, String registeredClaimValue,
			Builder tokenBuilder, Error error) {
		switch (registeredClaimKey) {
		case iss:
			try {
				tokenBuilder.withIssuer(registeredClaimValue);
			} catch (Exception e) {
				error.setError("RC003", e.getMessage());
				return null;
			}
			break;

		case exp:
			Date date = null;
			try {
				date = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").parse(registeredClaimValue);
			} catch (Exception e) {
				error.setError("RC004", "Date format error; expected yyyy/MM/dd HH:mm:ss");
				return null;
			}
			try {
				tokenBuilder.withExpiresAt(date);
			} catch (Exception e) {
				error.setError("RC005", e.getMessage());
				return null;
			}
			break;

		case sub:
			try {
				tokenBuilder.withSubject(registeredClaimValue);
			} catch (Exception e) {
				error.setError("RC006", e.getMessage());
				return null;
			}
			break;
		case aud:
			try {
				tokenBuilder.withAudience(registeredClaimValue);
			} catch (Exception e) {
				error.setError("RC007", e.getMessage());
				return null;
			}
			break;
		case nbf:
			Date dateNbf = null;
			try {
				dateNbf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").parse(registeredClaimValue);
			} catch (Exception e) {
				error.setError("RC008", "Date format error; expected yyyy/MM/dd HH:mm:ss");
				return null;
			}
			try {
				tokenBuilder.withNotBefore(dateNbf);
			} catch (Exception e) {
				error.setError("RC009", e.getMessage());
				return null;
			}
			break;
		case iat:
			Date dateIat = null;
			try {
				dateIat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").parse(registeredClaimValue);
			} catch (Exception e) {
				error.setError("RC010", "Date format error; expected yyyy/MM/dd HH:mm:ss");
				return null;
			}
			try {
				tokenBuilder.withIssuedAt(dateIat);
			} catch (Exception e) {
				error.setError("RC011", e.getMessage());
				return null;
			}
			break;
		case jti:
			try {
				tokenBuilder.withJWTId(registeredClaimValue);
			} catch (Exception e) {
				error.setError("RC012", e.getMessage());
				return null;
			}
			break;
		default:
			error.setError("RC013", "Unknown registered claim");
			return null;
		}
		return tokenBuilder;
	}

}
