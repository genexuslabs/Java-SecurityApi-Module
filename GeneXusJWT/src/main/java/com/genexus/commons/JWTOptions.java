package com.genexus.commons;

import org.bouncycastle.util.encoders.Hex;

import com.genexus.JWT.claims.PublicClaims;
import com.genexus.JWT.claims.RegisteredClaims;
import com.genexus.JWT.utils.RevocationList;
import com.genexus.securityapicommons.commons.SecurityAPIObject;
import com.genexus.securityapicommons.keys.CertificateX509;
import com.genexus.securityapicommons.keys.PrivateKeyManager;


public class JWTOptions extends SecurityAPIObject {

	private PublicClaims publicClaims;
	private RegisteredClaims registeredClaims;
	private byte[] secret;
	private RevocationList revocationList;
	private CertificateX509 certificate;
	private PrivateKeyManager privateKey;

	public JWTOptions() {
		publicClaims = new PublicClaims();
		registeredClaims = new RegisteredClaims();
		revocationList = new RevocationList();
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/

	public void setPrivateKey(PrivateKeyManager key) {
		this.privateKey = key;
	}
	
	public void setCertificate(CertificateX509 cert) {
		this.certificate = cert;
	}
	
	public void setSecret(String value) {

		try {
			secret = Hex.decode(value);
		} catch (Exception e) {
			this.error.setError("OP001", "Hexadecimal value expected");
			secret = null;
		}

	}

	public boolean addCustomTimeValidationClaim(String key, String value, String customTime) {
		this.registeredClaims.setTimeValidatingClaim(key, value, customTime, this.error);
		if (this.hasError()) {
			return false;
		} else {
			return true;
		}
	}

	public boolean addRegisteredClaim(String registeredClaimKey, String registeredClaimValue) {
		return registeredClaims.setClaim(registeredClaimKey, registeredClaimValue, this.error);
	}

	public boolean addPublicClaim(String publicClaimKey, String publicClaimValue) {
		return publicClaims.setClaim(publicClaimKey, publicClaimValue, this.error);
	}

	public void addRevocationList(RevocationList revocationList) {
		this.revocationList = revocationList;
	}

	public void deteleRevocationList() {
		this.revocationList = new RevocationList();
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

	public boolean hasPublicClaims() {
		return !publicClaims.isEmpty();
	}

	public boolean hasRegisteredClaims() {
		return !registeredClaims.isEmpty();
	}

	public RegisteredClaims getAllRegisteredClaims() {
		return this.registeredClaims;
	}

	public PublicClaims getAllPublicClaims() {
		return this.publicClaims;
	}

	public long getcustomValidationClaimValue(String key) {
		return this.registeredClaims.getClaimCustomValidationTime(key);
	}

	public boolean hasCustomTimeValidatingClaims() {
		return this.getAllRegisteredClaims().hasCustomValidationClaims();
	}


	public byte[] getSecret() {
		return this.secret;
	}

	public RevocationList getRevocationList() {
		return this.revocationList;
	}

	public CertificateX509 getCertificate() {
		return this.certificate;
	}
	
	public PrivateKeyManager getPrivateKey() {
		return this.privateKey;
	}
}
