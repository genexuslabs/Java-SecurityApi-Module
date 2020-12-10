package com.genexus.JWT;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.auth0.jwt.interfaces.Verification;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.genexus.JWT.claims.Claim;
import com.genexus.JWT.claims.HeaderParameters;
import com.genexus.JWT.claims.PrivateClaims;
import com.genexus.JWT.claims.PublicClaims;
import com.genexus.JWT.claims.RegisteredClaim;
import com.genexus.JWT.claims.RegisteredClaims;
import com.genexus.JWT.utils.JWTAlgorithm;
import com.genexus.JWT.utils.RevocationList;
import com.genexus.commons.JWTObject;
import com.genexus.commons.JWTOptions;
import com.genexus.securityapicommons.config.EncodingUtil;
import com.genexus.securityapicommons.keys.CertificateX509;
import com.genexus.securityapicommons.keys.PrivateKeyManager;
import com.genexus.securityapicommons.utils.SecurityUtils;

public class JWTCreator extends JWTObject {

	private int counter;

	public JWTCreator() {
		super();
		EncodingUtil eu = new EncodingUtil();
		eu.setEncoding("UTF8");
		this.counter = 0;

	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/
	public String doCreate(String algorithm, PrivateClaims privateClaims, JWTOptions options) {
		this.error.cleanError();
		if (options.hasError()) {
			this.error = options.getError();
			return "";
		}
		JWTAlgorithm alg = JWTAlgorithm.getJWTAlgorithm(algorithm, this.error);
		if (this.hasError()) {
			return "";
		}
		Builder tokenBuilder = JWT.create();
		if (!options.getHeaderParameters().isEmpty()) {
			HeaderParameters parameters = options.getHeaderParameters();
			tokenBuilder.withHeader(parameters.getMap());
		}
		tokenBuilder = doBuildPayload(tokenBuilder, privateClaims, options);
		if (this.hasError()) {
			return "";
		}
		Algorithm algorithmType = null;
		if (JWTAlgorithm.isPrivate(alg)) {
			CertificateX509 cert = options.getCertificate();
			PrivateKeyManager key = options.getPrivateKey();
			if (cert.hasError()) {
				this.error = cert.getError();
				return "";
			}
			if (key.hasError()) {
				this.error = key.getError();
				return "";
			}
			algorithmType = JWTAlgorithm.getAsymmetricAlgorithm(alg, key, cert, this.error);
			if (this.hasError()) {
				return "";
			}
		} else {

			algorithmType = JWTAlgorithm.getSymmetricAlgorithm(alg, options.getSecret(), this.error);
			if (this.hasError()) {
				return "";
			}
		}
		String signedJwt = "";
		try {
			signedJwt = tokenBuilder.sign(algorithmType);
		} catch (Exception e) {
			this.error.setError("JW003", e.getMessage());
			return "";
		}

		return signedJwt;
	}

	public boolean doVerify(String token, String expectedAlgorithm, PrivateClaims privateClaims, JWTOptions options) {
		return doVerify(token, expectedAlgorithm, privateClaims, options, true, true);
	}

	public boolean doVerifyJustSignature(String token, String expectedAlgorithm, JWTOptions options) {
		return doVerify(token, expectedAlgorithm, null, options, false, false);
	}

	public boolean doVerifySignature(String token, String expectedAlgorithm, JWTOptions options) {
		return doVerify(token, expectedAlgorithm, null, options, false, true);
	}

	public String getPayload(String token) {
		String res = "";
		try {
			res = getTokenPart(token, "payload");
		} catch (Exception e) {
			this.error.setError("JW009", e.getMessage());
			return "";
		}
		return res;

	}

	public String getHeader(String token) {
		String res = "";
		try {
			res = getTokenPart(token, "header");
		} catch (Exception e) {
			this.error.setError("JW010", e.getMessage());
			return "";
		}
		return res;
	}

	public String getTokenID(String token) {
		String res = "";
		try {

			res = getTokenPart(token, "id");
		} catch (Exception e) {
			this.error.setError("JW011", e.getMessage());
			return "";
		}
		return res;
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

	private boolean doVerify(String token, String expectedAlgorithm, PrivateClaims privateClaims, JWTOptions options,
			boolean verifyClaims, boolean verifyRegClaims) {
		this.error.cleanError();
		if (options.hasError()) {
			this.error = options.getError();
			return false;
		}
		DecodedJWT decodedJWT = null;
		try {
			decodedJWT = JWT.decode(token);

		} catch (Exception e) {
			this.error.setError("JW005", e.getMessage());
			return false;
		}
		if (isRevoqued(decodedJWT, options)) {
			return false;
		}
		if (verifyClaims) {
			if (!verifyPrivateClaims(decodedJWT, privateClaims, options) || !verifyHeader(decodedJWT, options)) {
				return false;
			}
		}
		String algorithm = decodedJWT.getAlgorithm();
		JWTAlgorithm alg = JWTAlgorithm.getJWTAlgorithm(algorithm, this.error);
		if (this.hasError()) {
			return false;
		}
		JWTAlgorithm expectedJWTAlgorithm = JWTAlgorithm.getJWTAlgorithm(expectedAlgorithm, this.error);
		if (alg.compareTo(expectedJWTAlgorithm) != 0 || this.hasError()) {
			this.error.setError("JW008", "Expected algorithm does not match token algorithm");
			return false;
		}

		Algorithm algorithmType = null;
		if (JWTAlgorithm.isPrivate(alg)) {
			CertificateX509 cert = options.getCertificate();
			if (cert.hasError()) {
				this.error = cert.getError();
				return false;
			}
			algorithmType = JWTAlgorithm.getAsymmetricAlgorithm(alg, null, cert, this.error);
			if (this.hasError()) {
				return false;
			}
		} else {
			algorithmType = JWTAlgorithm.getSymmetricAlgorithm(alg, options.getSecret(), this.error);
			if (this.hasError()) {
				return false;
			}
		}
		Verification verification = JWT.require(algorithmType);
		verification = buildVerification(verification, options, verifyRegClaims);
		if (this.hasError()) {
			return false;
		}

		try {
			JWTVerifier verifier = verification.build();
			DecodedJWT decodedToken = JWT.decode(token);

			verifier.verify(decodedToken);
		} catch (Exception e) {
			error.setError("JW006", e.getMessage());
			return false;
		}

		return true;

	}

	private String getTokenPart(String token, String part) throws Exception {
		DecodedJWT decodedToken = JWT.decode(token);
		String base64Part = "";
		switch (part) {
		case "payload":
			base64Part = decodedToken.getPayload();
			break;
		case "header":
			base64Part = decodedToken.getHeader();
			break;
		case "id":
			return decodedToken.getId();
		default:
			error.setError("JW007", "Unknown token segment");
			return "";
		}
		byte[] base64Bytes = Base64.decodeBase64(base64Part);
		EncodingUtil eu = new EncodingUtil();
		String plainTextPart = eu.getString(base64Bytes);
		if (eu.hasError()) {
			this.error = eu.getError();
			return "";
		}
		return plainTextPart;
	}

	private boolean isRevoqued(DecodedJWT decodedJWT, JWTOptions options) {
		RevocationList rList = options.getRevocationList();
		return rList.isInRevocationList(decodedJWT.getId());
	}

	private Verification buildVerification(Verification verification, JWTOptions options, boolean verifyClaims) {
		// Adding registered claims
		if (!verifyClaims) {
			return verification;
		}
		if (options.hasRegisteredClaims()) {
			RegisteredClaims registeredClaims = options.getAllRegisteredClaims();
			List<Claim> registeredC = registeredClaims.getAllClaims();
			for (int z = 0; z < registeredC.size(); z++) {
				if (RegisteredClaim.exists(registeredC.get(z).getKey())) {
					if (!RegisteredClaim.isTimeValidatingClaim(registeredC.get(z).getKey())) {
						verification = RegisteredClaim.getVerificationWithClaim(registeredC.get(z).getKey(),
								registeredC.get(z).getValue(), 0, verification, error);
					} else {
						verification = RegisteredClaim.getVerificationWithClaim(registeredC.get(z).getKey(),
								registeredC.get(z).getValue(),
								registeredClaims.getClaimCustomValidationTime(registeredC.get(z).getKey()),
								verification, error);
					}
					if (this.hasError()) {
						return null;
					}
				} else {
					error.setError("JW002", registeredC.get(z).getKey() + " wrong registered claim key");
					return null;
				}
			}
		}
		return verification;

	}

	private Builder doBuildPayload(Builder tokenBuilder, PrivateClaims privateClaims, JWTOptions options) {
		// ****START BUILD PAYLOAD****//
		// Adding private claims
		List<Claim> privateC = privateClaims.getAllClaims();
		for (int i = 0; i < privateC.size(); i++) {
			try {
				if (privateC.get(i).getNestedClaims() != null) {
					tokenBuilder.withClaim(privateC.get(i).getKey(), privateC.get(i).getNestedClaims().getNestedMap());
				} else {
					tokenBuilder.withClaim(privateC.get(i).getKey(), privateC.get(i).getValue());
				}
			} catch (Exception e) {
				this.error.setError("JW004", e.getMessage());
				return null;
			}
		}
		// Adding public claims
		if (options.hasPublicClaims()) {
			PublicClaims publicClaims = options.getAllPublicClaims();
			List<Claim> publicC = publicClaims.getAllClaims();
			for (int j = 0; j < publicC.size(); j++) {
				try {
					tokenBuilder.withClaim(publicC.get(j).getKey(), publicC.get(j).getValue());
				} catch (Exception e) {
					this.error.setError("JW003", e.getMessage());
					return null;
				}
			}
		}
		// Adding registered claims
		if (options.hasRegisteredClaims()) {
			RegisteredClaims registeredClaims = options.getAllRegisteredClaims();
			List<Claim> registeredC = registeredClaims.getAllClaims();
			for (int z = 0; z < registeredC.size(); z++) {
				if (RegisteredClaim.exists(registeredC.get(z).getKey())) {
					tokenBuilder = RegisteredClaim.getBuilderWithClaim(registeredC.get(z).getKey(),
							registeredC.get(z).getValue(), tokenBuilder, this.error);
					if (this.hasError()) {
						return null;
					}
				} else {
					error.setError("JW002", registeredC.get(z).getKey() + " wrong registered claim key");
					return null;
				}
			}
		}
		// ****END BUILD PAYLOAD****//
		return tokenBuilder;
	}

	private boolean verifyPrivateClaims(DecodedJWT decodedJWT, PrivateClaims privateClaims, JWTOptions options) {
		RegisteredClaims registeredClaims = options.getAllRegisteredClaims();
		PublicClaims publicClaims = options.getAllPublicClaims();
		if (privateClaims == null || privateClaims.isEmpty()) {
			return true;
		}
		String base64Part = decodedJWT.getPayload();
		byte[] base64Bytes = Base64.decodeBase64(base64Part);
		EncodingUtil eu = new EncodingUtil();
		String plainTextPart = eu.getString(base64Bytes);
		HashMap<String, Object> map = new HashMap<String, Object>();
		ObjectMapper mapper = new ObjectMapper();

		try {
			map = (HashMap<String, Object>) mapper.readValue(plainTextPart, new TypeReference<Map<String, Object>>() {
			});
		} catch (Exception e) {
			this.error.setError("JW009", "Cannot parse JWT payload");
			return false;
		}
		this.counter = 0;
		boolean validation = verifyNestedClaims(privateClaims.getNestedMap(), map, registeredClaims, publicClaims);
		int pClaimsCount = countingPrivateClaims(privateClaims.getNestedMap(), 0);
		if (validation && !(this.counter == pClaimsCount)) {
			return false;
		}
		return validation;
	}

	private boolean verifyNestedClaims(Map<String, Object> pclaimMap, Map<String, Object> map,
			RegisteredClaims registeredClaims, PublicClaims publicClaims) {
		List<String> mapClaimKeyList = new ArrayList<String>(map.keySet());
		List<String> pClaimKeyList = new ArrayList<String>(pclaimMap.keySet());
		if (pClaimKeyList.size() > pClaimKeyList.size()) {
			return false;
		}
		for (String mapKey : mapClaimKeyList) {

			if (!isRegistered(mapKey, registeredClaims) && !isPublic(mapKey, publicClaims)) {

				this.counter++;
				if (!pclaimMap.containsKey(mapKey)) {
					return false;
				}

				Object op = pclaimMap.get(mapKey);
				Object ot = map.get(mapKey);

				if (op instanceof String && ot instanceof String) {

					if (!SecurityUtils.compareStrings(((String) op).trim(), ((String) ot).trim())) {
						return false;
					}
				} else if (op instanceof HashMap && ot instanceof HashMap) {
					@SuppressWarnings("unchecked")
					boolean flag = verifyNestedClaims((HashMap<String, Object>) op, (HashMap<String, Object>) ot,
							registeredClaims, publicClaims);
					if (!flag) {
						return false;
					}
				} else {
					return false;
				}
			}
		}
		return true;
	}

	private boolean isRegistered(String claimKey, RegisteredClaims registeredClaims) {

		List<Claim> registeredClaimsList = registeredClaims.getAllClaims();
		for (Claim s : registeredClaimsList) {
			if (SecurityUtils.compareStrings(s.getKey().trim(), claimKey.trim())) {
				return true;
			}
		}
		return false;
	}

	private boolean isPublic(String claimKey, PublicClaims publicClaims) {
		List<Claim> publicClaimsList = publicClaims.getAllClaims();
		for (Claim s : publicClaimsList) {
			if (SecurityUtils.compareStrings(s.getKey().trim(), claimKey.trim())) {
				return true;
			}
		}
		return false;
	}

	@SuppressWarnings("unchecked")
	private int countingPrivateClaims(Map<String, Object> map, int counter) {
		List<String> list = new ArrayList<String>(map.keySet());
		for (String s : list) {
			counter++;
			Object obj = map.get(s);
			if (obj instanceof HashMap) {
				counter = countingPrivateClaims((HashMap<String, Object>) obj, counter);
			}
		}
		return counter;
	}

	private boolean verifyHeader(DecodedJWT decodedJWT, JWTOptions options) {
		HeaderParameters parameters = options.getHeaderParameters();
		int claimsNumber = getHeaderClaimsNumber(decodedJWT);
		if (parameters.isEmpty() && claimsNumber == 2) {
			return true;
		}
		if (parameters.isEmpty() && claimsNumber > 2) {
			return false;
		}
		List<String> allParms = parameters.getAll();
		if (allParms.size() + 2 != claimsNumber) {
			return false;
		}
		Map<String, Object> map = parameters.getMap();
		for (String s : allParms) {

			if (decodedJWT.getHeaderClaim(s) == null) {
				return false;
			}
			com.auth0.jwt.interfaces.Claim c = decodedJWT.getHeaderClaim(s);
			String claimValue = null;
			try {
				claimValue = c.asString().trim();
			} catch (NullPointerException e) {
				return false;
			}
			String optionsValue = ((String) map.get(s)).trim();
			if (!SecurityUtils.compareStrings(claimValue, optionsValue)) {
				return false;
			}
		}
		return true;

	}

	private int getHeaderClaimsNumber(DecodedJWT decodedJWT) {
		String base64Part = decodedJWT.getHeader();
		byte[] base64Bytes = Base64.decodeBase64(base64Part);
		EncodingUtil eu = new EncodingUtil();
		String plainTextPart = eu.getString(base64Bytes);
		HashMap<String, Object> map = new HashMap<String, Object>();
		ObjectMapper mapper = new ObjectMapper();

		try {
			map = (HashMap<String, Object>) mapper.readValue(plainTextPart, new TypeReference<Map<String, Object>>() {
			});
		} catch (Exception e) {
			return 0;
		}
		return map.size();

	}

}
