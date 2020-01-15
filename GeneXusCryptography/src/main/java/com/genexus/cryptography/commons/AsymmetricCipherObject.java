package com.genexus.cryptography.commons;

import com.genexus.securityapicommons.commons.SecurityAPIObject;
import com.genexus.securityapicommons.keys.CertificateX509;
import com.genexus.securityapicommons.keys.PrivateKeyManager;

/**
 * @author sgrampone
 *
 */
public abstract class AsymmetricCipherObject extends SecurityAPIObject {

	/**
	 * AsymmetricCipherObject constructor
	 */
	public AsymmetricCipherObject() {
		super();
	}

	public abstract String doEncrypt_WithPrivateKey(String hashAlgorithm, String asymmetricEncryptionPadding,
			PrivateKeyManager key, String plainText);

	public abstract String doEncrypt_WithPublicKey(String hashAlgorithm, String asymmetricEncryptionPadding,
			CertificateX509 certificate, String plainText);

	public abstract String doDecrypt_WithPrivateKey(String hashAlgorithm, String asymmetricEncryptionPadding,
			PrivateKeyManager key, String encryptedInput);

	public abstract String doDecrypt_WithPublicKey(String hashAlgorithm, String asymmetricEncryptionPadding,
			CertificateX509 certificate, String encryptedInput);

}
