package com.genexus.cryptography.asymmetric;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.util.encoders.Base64;

import com.genexus.cryptography.asymmetric.utils.AsymmetricSigningAlgorithm;
import com.genexus.cryptography.commons.AsymmetricSignerObject;
import com.genexus.cryptography.hash.Hashing;
import com.genexus.cryptography.hash.utils.HashAlgorithm;
import com.genexus.securityapicommons.commons.Certificate;
import com.genexus.securityapicommons.commons.PrivateKey;
import com.genexus.securityapicommons.config.EncodingUtil;
import com.genexus.securityapicommons.keys.CertificateX509;
import com.genexus.securityapicommons.keys.PrivateKeyManager;
import com.genexus.securityapicommons.utils.SecurityUtils;



public class AsymmetricSigner extends AsymmetricSignerObject {

	/**
	 * AsymmetricSigner class constructor
	 */
	public AsymmetricSigner() {
		super();
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/


	/**
	 * Implements signature calculationwith RSA or ECDSA keys.
	 * 
	 * @param path
	 *            String path of the key/certificate file
	 * @param hashAlgorithm
	 *            String HashAlgorithm enum, algorithm name
	 * @param plainText
	 *            String UTF-8 text to sign
	 * @param options
	 *            Options data type to sel alias and pasword for pkcs12 certificate
	 * @return String Base64 signature of plainText text
	 */
	@Override
	public String doSign(PrivateKeyManager key, String hashAlgorithm, String plainText) {
		return doSignPKCS12(key, hashAlgorithm, plainText);
	}

	/**
	 * Implements signature verification with RSA or ECDSA keys
	 * 
	 * @param path
	 *            String path of the key/certificate file
	 * @param plainText
	 *            String UTF-8 signed text
	 * @param signature
	 *            String Base64 signature of plainText
	 * @param options
	 *            Options data type to sel alias and pasword for pkcs12 certificate
	 * @return boolean true if signature is valid for the specified parameters,
	 *         false if it is invalid
	 */
	@Override
	public boolean doVerify(CertificateX509 cert, String plainText, String signature) {
		return doVerifyPKCS12(cert, plainText, signature);
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

	/**
	 * Implements signature calculationwith RSA or ECDSA keys.
	 * 
	 * @param path
	 *            String path of the key/certificate file
	 * @param hashAlgorithm
	 *            String HashAlgorithm enum, algorithm name
	 * @param alias
	 *            String alias of the certificate/keystore in pkcs12 format
	 * @param password
	 *            String password of the certificate/keystore in pkcs12 format
	 * @param plainText
	 *            String UTF-8 text to sign
	 * @return String Base64 signature of plainText text
	 */
	private String doSignPKCS12(PrivateKey key, String hashAlgorithm, String plainText) {
		this.error.cleanError();
		HashAlgorithm hash = HashAlgorithm.getHashAlgorithm(hashAlgorithm, this.error);
		if (this.error.existsError()) {
			return "";
		}
		PrivateKeyManager keyMan = (PrivateKeyManager)key;
		String algorithm = keyMan.getPrivateKeyAlgorithm();
		if (keyMan.getError().existsError()) {
			this.error = keyMan.getError();
			return "";
		}
		
		if (SecurityUtils.compareStrings(algorithm, "RSA")) {
			return signRSA(hash, plainText, keyMan);
		}
		if (SecurityUtils.compareStrings(algorithm, "ECDSA")) {
			return signECDSA(hash, plainText, keyMan);
		}
		this.error.setError("AE047", "Unrecognized signing algorithm " + algorithm);
		return "";
	}
	
	/**
	 * Implements signature verification with RSA or ECDSA keys
	 * 
	 * @param path
	 *            String path of the key/certificate file
	 * @param alias
	 *            String alias of the certificate/keystore in pkcs12 format
	 * @param password
	 *            String password of the certificate/keystore in pkcs12 format
	 * @param plainText
	 *            String UTF-8 signed text
	 * @param signature
	 *            String Base64 signature of plainText
	 * @return boolean true if signature is valid for the specified parameters,
	 *         false if it is invalid
	 */
	private boolean doVerifyPKCS12(Certificate certificate, String plainText, String signature) {
		this.error.cleanError();
		CertificateX509 cert = (CertificateX509)certificate;
		if (!cert.Inicialized() || cert.hasError()) {
			this.error = cert.getError();
			return false;
		}
		AsymmetricSigningAlgorithm asymmetricSigningAlgorithm = AsymmetricSigningAlgorithm
				.getAsymmetricSigningAlgorithm(cert.getPublicKeyAlgorithm(), this.error);
		if (this.error.existsError()) {
			return false;
		}
		switch (asymmetricSigningAlgorithm) {
		case RSA:
			return verifyRSA(plainText, signature, cert);
		case ECDSA:
			return verifyECDSA(plainText, signature, cert);
		default:
			this.error.setError("AE048", "Cannot verify signature");
			return false;
		}

	}
	
	/**
	 * Implements signature verification with RSA keys, hash value NONE is not
	 * valid. Uses hash specified on certificate by default
	 * 
	 * @param plainText
	 *            String UTF-8 signed text
	 * @param signature
	 *            String Base64 signature of plainText
	 * @param km
	 *            KeyManager Data Type loaded with keys and key information
	 * @return boolean true if signature is valid for the specified parameters,
	 *         false if it is invalid
	 */
	private boolean verifyRSA(String plainText, String signature, CertificateX509 cert) {
		HashAlgorithm hashAlgorithm = HashAlgorithm.valueOf(cert.getPublicKeyHash());
		if (HashAlgorithm.NONE != hashAlgorithm) {
			EncodingUtil eu = new EncodingUtil();
			byte[] inputText = eu.getBytes(plainText);
			if(eu.hasError()) {
				this.error = eu.getError();
				return false;
			}
			Hashing digest = new Hashing();
			Digest hash = digest.createHash(hashAlgorithm);
			if (digest.getError().existsError()) {
				this.error = digest.getError();
				return false;
			}
			RSADigestSigner signerRSA = new RSADigestSigner(hash);
			AsymmetricKeyParameter asymmetricKeyParameter = cert.getPublicKeyParameterForSigning();
			if (this.error.existsError()) {
				return false;
			}
			signerRSA.init(false, asymmetricKeyParameter);
			signerRSA.update(inputText, 0, inputText.length);
			byte[] signatureBytes = Base64.decode(signature);
			if (signatureBytes == null || signatureBytes.length == 0) {
				this.error.setError("AE049", "Error on signature verification");
				return false;
			}
			this.error.cleanError();
			return signerRSA.verifySignature(signatureBytes);
		}
		this.error.setError("AE050", "Hashalgorithm cannot be NONE");
		return false;
	}

	/**
	 * Implements signature verification with ECDSA keys, if no hash is defined uses
	 * default SHA1
	 * 
	 * @param plainText
	 *            String UTF-8 signed text
	 * @param signature
	 *            String Base64 signature of plainText
	 * @param km
	 *            KeyManager Data Type loaded with keys and key information
	 * @return boolean true if signature is valid for the specified parameters,
	 *         false if it is invalid
	 */
	private boolean verifyECDSA(String plainText, String signature, CertificateX509 cert) {
		HashAlgorithm hashAlgorithm = null;
		
		if (SecurityUtils.compareStrings(cert.getPublicKeyHash(), "ECDSA")) {
			hashAlgorithm = HashAlgorithm.SHA1;
		} else {
			hashAlgorithm = HashAlgorithm.valueOf(cert.getPublicKeyHash());
		}
		Hashing hash = new Hashing();
		Digest digest = hash.createHash(hashAlgorithm);
		if (hash.getError().existsError()) {
			this.error = hash.getError();
			return false;
		}
		ECDSASigner dsaSigner = new ECDSASigner();
		DSADigestSigner digestSigner = new DSADigestSigner(dsaSigner, digest);
		AsymmetricKeyParameter asymmetricKeyParameter = cert.getPublicKeyParameterForSigning();
		if (this.error.existsError()) {
			return false;
		}
		digestSigner.init(false, asymmetricKeyParameter);
		EncodingUtil eu = new EncodingUtil();
		byte[] input = eu.getBytes(plainText);
		if(eu.hasError()) {
			this.error = eu.getError();
			return false;
		}
		digestSigner.update(input, 0, input.length);
		byte[] signatureBytes = Base64.decode(signature);
		if (signatureBytes == null || signatureBytes.length == 0) {
			this.error.setError("AE051", "Error on signature verification");
			return false;
		}
		this.error.cleanError();
		return digestSigner.verifySignature(signatureBytes);

	}

	/**
	 * Implements ECDSA signature. Uses specified hash value or SHA1 for default
	 * 
	 * @param hashAlgorithm
	 *            HashAlgorithm enum, algorithm name
	 * @param plainText
	 *            String UTF-8 to sign
	 * @param km
	 *            KeyManager Data Type loaded with keys and key information
	 * @return String Base64 ECDSA signature of plainText
	 */
	private String signECDSA(HashAlgorithm hashAlgorithm, String plainText, PrivateKeyManager km) {
		Hashing hash = new Hashing();
		Digest digest = hash.createHash(hashAlgorithm);
		if (hash.getError().existsError()) {
			this.error = hash.getError();
			return "";
		}
		ECDSASigner dsaSigner = new ECDSASigner();
		DSADigestSigner digestSigner = new DSADigestSigner(dsaSigner, digest);
		AsymmetricKeyParameter asymmetricKeyParameter = km.getPrivateKeyParameterForSigning();
		if (this.error.existsError()) {
			return "";
		}
		digestSigner.init(true, asymmetricKeyParameter);
		EncodingUtil eu = new EncodingUtil();
		byte[] input = eu.getBytes(plainText);
		if(eu.hasError()) {
			this.error=eu.getError();
			return "";
		}
		digestSigner.update(input, 0, input.length);
		byte[] output = digestSigner.generateSignature();
		if (output == null || output.length == 0) {
			this.error.setError("AE052", "Error on signing");
		}
		this.error.cleanError();
		return new String(Base64.encode(output));

	}

	/**
	 * Implements RSSA signature. Hash NONE is not a valid value
	 * 
	 * @param hashAlgorithm
	 *            HashAlgorithm enum, algorithm name
	 * @param plainText
	 *            String UTF-8 to sign
	 * @param km
	 *            KeyManager Data Type loaded with keys and key information
	 * @return String Base64 RSA signature of plainText
	 */
	private String signRSA(HashAlgorithm hashAlgorithm, String plainText, PrivateKeyManager km) {
		if (HashAlgorithm.NONE != hashAlgorithm) {
			EncodingUtil eu = new EncodingUtil();
			byte[] inputText = eu.getBytes(plainText);
			if(eu.hasError()) {
				this.error=eu.getError();
				return "";
			}
			Hashing digest = new Hashing();
			Digest hash = digest.createHash(hashAlgorithm);
			if (digest.getError().existsError()) {
				this.error = digest.getError();
				return "";
			}
			RSADigestSigner signerRSA = new RSADigestSigner(hash);
			AsymmetricKeyParameter asymmetricKeyParameter = km.getPrivateKeyParameterForSigning();
			if (this.error.existsError()) {

				return "";
			}
			signerRSA.init(true, asymmetricKeyParameter);
			signerRSA.update(inputText, 0, inputText.length);
			byte[] outputBytes;
			try {
				outputBytes = signerRSA.generateSignature();
			} catch (DataLengthException | CryptoException e) {
				this.error.setError("AE053", "RSA signing error");
				e.printStackTrace();
				return "";
			}
			this.error.cleanError();
			return new String(Base64.encode(outputBytes));
		}
		this.error.setError("AE054", "HashAlgorithm cannot be NONE");
		return "";
	}

}

