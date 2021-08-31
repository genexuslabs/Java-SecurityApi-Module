package com.genexus.cryptography.asymmetric;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

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
	 * @param path          String path of the key/certificate file
	 * @param hashAlgorithm String HashAlgorithm enum, algorithm name
	 * @param plainText     String UTF-8 text to sign
	 * @param options       Options data type to sel alias and pasword for pkcs12
	 *                      certificate
	 * @return String Base64 signature of plainText text
	 */
	@Override
	public String doSign(PrivateKeyManager key, String hashAlgorithm, String plainText) {
		EncodingUtil eu = new EncodingUtil();
		byte[] inputText = eu.getBytes(plainText);
		if (eu.hasError()) {
			this.error = eu.getError();
			return "";
		}
		InputStream is = new ByteArrayInputStream(inputText);
		return doSignPKCS12(key, hashAlgorithm, is);
	}

	@Override
	public String doSignFile(PrivateKeyManager key, String hashAlgorithm, String path) {
		InputStream input = SecurityUtils.getFileStream(path, this.error);
		if (this.hasError()) {
			return "";
		}
		return doSignPKCS12(key, hashAlgorithm, input);
	}

	/**
	 * Implements signature verification with RSA or ECDSA keys
	 * 
	 * @param path      String path of the key/certificate file
	 * @param plainText String UTF-8 signed text
	 * @param signature String Base64 signature of plainText
	 * @param options   Options data type to sel alias and pasword for pkcs12
	 *                  certificate
	 * @return boolean true if signature is valid for the specified parameters,
	 *         false if it is invalid
	 */
	@Override
	public boolean doVerify(CertificateX509 cert, String plainText, String signature) {
		EncodingUtil eu = new EncodingUtil();
		byte[] inputText = eu.getBytes(plainText);
		if (eu.hasError()) {
			this.error = eu.getError();
			return false;
		}
		InputStream is = new ByteArrayInputStream(inputText);
		return doVerifyPKCS12(cert, is, signature);
	}

	@Override
	public boolean doVerifyFile(CertificateX509 cert, String path, String signature) {
		InputStream input = SecurityUtils.getFileStream(path, this.error);
		if (this.hasError()) {
			return false;
		}
		return doVerifyPKCS12(cert, input, signature);
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

	/**
	 * Implements signature calculationwith RSA or ECDSA keys.
	 * 
	 * @param path          String path of the key/certificate file
	 * @param hashAlgorithm String HashAlgorithm enum, algorithm name
	 * @param alias         String alias of the certificate/keystore in pkcs12
	 *                      format
	 * @param password      String password of the certificate/keystore in pkcs12
	 *                      format
	 * @param plainText     String UTF-8 text to sign
	 * @return String Base64 signature of plainText text
	 */
	private String doSignPKCS12(PrivateKey key, String hashAlgorithm, InputStream input) {
		this.error.cleanError();
		HashAlgorithm hash = HashAlgorithm.getHashAlgorithm(hashAlgorithm, this.error);
		if (this.error.existsError()) {
			return "";
		}
		PrivateKeyManager keyMan = (PrivateKeyManager) key;
		String algorithm = keyMan.getPrivateKeyAlgorithm();
		if (keyMan.getError().existsError()) {
			this.error = keyMan.getError();
			return "";
		}

		if (SecurityUtils.compareStrings(algorithm, "RSA")) {
			return signRSA(hash, input, keyMan);
		}
		if (SecurityUtils.compareStrings(algorithm, "ECDSA")) {
			return signECDSA(hash, input, keyMan);
		}
		this.error.setError("AE047", "Unrecognized signing algorithm " + algorithm);
		return "";
	}

	/**
	 * Implements signature verification with RSA or ECDSA keys
	 * 
	 * @param path      String path of the key/certificate file
	 * @param alias     String alias of the certificate/keystore in pkcs12 format
	 * @param password  String password of the certificate/keystore in pkcs12 format
	 * @param plainText String UTF-8 signed text
	 * @param signature String Base64 signature of plainText
	 * @return boolean true if signature is valid for the specified parameters,
	 *         false if it is invalid
	 */
	private boolean doVerifyPKCS12(Certificate certificate, InputStream input, String signature) {
		this.error.cleanError();
		CertificateX509 cert = (CertificateX509) certificate;
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
			return verifyRSA(input, signature, cert);
		case ECDSA:
			return verifyECDSA(input, signature, cert);
		default:
			this.error.setError("AE048", "Cannot verify signature");
			return false;
		}

	}

	/**
	 * Implements signature verification with RSA keys, hash value NONE is not
	 * valid. Uses hash specified on certificate by default
	 * 
	 * @param plainText String UTF-8 signed text
	 * @param signature String Base64 signature of plainText
	 * @param km        KeyManager Data Type loaded with keys and key information
	 * @return boolean true if signature is valid for the specified parameters,
	 *         false if it is invalid
	 */
	private boolean verifyRSA(InputStream input, String signature, CertificateX509 cert) {
		HashAlgorithm hashAlgorithm = HashAlgorithm.valueOf(cert.getPublicKeyHash());
		if (HashAlgorithm.NONE != hashAlgorithm) {
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
			byte[] buffer = new byte[8192];
			int n;
			byte[] signatureBytes = null;
			try {
				while ((n = input.read(buffer)) > 0) {
					signerRSA.update(buffer, 0, n);
				}
			} catch (Exception e) {
				error.setError("AE057", e.getMessage());
				return false;
			}
			signatureBytes = Base64.decode(signature);
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
	 * @param plainText String UTF-8 signed text
	 * @param signature String Base64 signature of plainText
	 * @param km        KeyManager Data Type loaded with keys and key information
	 * @return boolean true if signature is valid for the specified parameters,
	 *         false if it is invalid
	 */
	private boolean verifyECDSA(InputStream input, String signature, CertificateX509 cert) {
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
		byte[] buffer = new byte[8192];
		int n;
		byte[] signatureBytes = null;
		try {
			while ((n = input.read(buffer)) > 0) {
				digestSigner.update(buffer, 0, n);
			}

			signatureBytes = Base64.decode(signature);
		} catch (Exception e) {
			error.setError("AE056", e.getMessage());
			return false;
		}
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
	 * @param hashAlgorithm HashAlgorithm enum, algorithm name
	 * @param plainText     String UTF-8 to sign
	 * @param km            KeyManager Data Type loaded with keys and key
	 *                      information
	 * @return String Base64 ECDSA signature of plainText
	 */
	private String signECDSA(HashAlgorithm hashAlgorithm, InputStream input, PrivateKeyManager km) {
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
		byte[] buffer = new byte[8192];
		int n;
		byte[] output = null;
		try {
			while ((n = input.read(buffer)) > 0) {
				digestSigner.update(buffer, 0, n);
			}

			// digestSigner.update(input, 0, input.length);
			output = digestSigner.generateSignature();
		} catch (Exception e) {
			error.setError("AE055", e.getMessage());
			return "";
		}
		if (output == null || output.length == 0) {
			this.error.setError("AE052", "Error on signing");
		}
		this.error.cleanError();
		return new String(Base64.encode(output));

	}

	/**
	 * Implements RSSA signature. Hash NONE is not a valid value
	 * 
	 * @param hashAlgorithm HashAlgorithm enum, algorithm name
	 * @param plainText     String UTF-8 to sign
	 * @param km            KeyManager Data Type loaded with keys and key
	 *                      information
	 * @return String Base64 RSA signature of plainText
	 */
	private String signRSA(HashAlgorithm hashAlgorithm, InputStream input, PrivateKeyManager km) {
		if (hashAlgorithm != HashAlgorithm.NONE) {
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
			byte[] buffer = new byte[8192];
			int n;
			byte[] outputBytes;
			try {
				while ((n = input.read(buffer)) > 0) {
					signerRSA.update(buffer, 0, n);
				}
				outputBytes = signerRSA.generateSignature();
			} catch (DataLengthException | CryptoException | IOException e) {
				this.error.setError("AE053", "RSA signing error");
				return "";
			}
			this.error.cleanError();
			return new String(Base64.encode(outputBytes));
		}
		this.error.setError("AE054", "HashAlgorithm cannot be NONE");
		return "";
	}

}
