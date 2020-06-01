package com.genexus.JWT;

import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.auth0.jwt.interfaces.Verification;
import com.genexus.JWT.claims.Claim;
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

	public JWTCreator() {
		super();
		EncodingUtil eu = new EncodingUtil();
		eu.setEncoding("UTF8");
	
	}
	
	/******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/
	public String doCreate(String algorithm, PrivateClaims privateClaims, JWTOptions options) {
		if (options.hasError()) {
			this.error = options.getError();
			return "";
		}
		JWTAlgorithm alg = JWTAlgorithm.getJWTAlgorithm(algorithm, this.error);
		if (this.hasError()) {
			return "";
		}
		Builder tokenBuilder = JWT.create();
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
		if (isRevoqued(decodedJWT, options) || !verifyPrivateClaims(decodedJWT, privateClaims)) {
			return false;
		}
		String algorithm = decodedJWT.getAlgorithm();
		JWTAlgorithm alg = JWTAlgorithm.getJWTAlgorithm(algorithm, this.error);
		if (this.hasError()) {
			return false;
		}
		JWTAlgorithm expectedJWTAlgorithm = JWTAlgorithm.getJWTAlgorithm(expectedAlgorithm, this.error);
        if(alg.compareTo(expectedJWTAlgorithm) != 0 || this.hasError())
        {
            this.error.setError("JW008", "Expected algorithm does not match token algorithm");
            return false;
        }
        
		Algorithm algorithmType = null;
		if (JWTAlgorithm.isPrivate(alg)) {
			CertificateX509 cert = options.getCertificate();
			PrivateKeyManager key = options.getPrivateKey();
			if (cert.hasError()) {
				this.error = cert.getError();
				return false;
			}
			if (key.hasError()) {
				this.error = key.getError();
				return false;
			}
			algorithmType = JWTAlgorithm.getAsymmetricAlgorithm(alg, key, cert, this.error);
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
		verification = buildVerification(verification, options);
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

	public String getPayload(String token) {
		return getTokenPart(token, "payload");

	}

	public String getHeader(String token) {
		return getTokenPart(token, "header");
	}

	public String getTokenID(String token) {
		return getTokenPart(token, "id");
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

	private String getTokenPart(String token, String part) {
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

	private Verification buildVerification(Verification verification, JWTOptions options) {
		// Adding registered claims
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
				tokenBuilder.withClaim(privateC.get(i).getKey(), privateC.get(i).getValue());
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
	
	private boolean verifyPrivateClaims(DecodedJWT decodedJWT, PrivateClaims privateClaims)
	{
		if(privateClaims == null || privateClaims.isEmpty())
		{
			return true;
		}
		Map<String, com.auth0.jwt.interfaces.Claim> map = decodedJWT.getClaims();
		
		List<Claim> claims = privateClaims.getAllClaims();
		for(int i= 0; i < claims.size(); i++)
		{
			Claim c = claims.get(i);
			if(!map.containsKey(c.getKey()))
			{
				return false;
			}
			com.auth0.jwt.interfaces.Claim claim = map.get(c.getKey());
			if(!SecurityUtils.compareStrings(claim.asString().trim(), c.getValue().trim()))
			{
				return false;
			}
		}
		return true;
	}
	


}
