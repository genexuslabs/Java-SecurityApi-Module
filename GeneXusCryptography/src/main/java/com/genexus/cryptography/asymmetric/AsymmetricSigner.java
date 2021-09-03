package com.genexus.cryptography.asymmetric;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
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
	
	@Override
	public String doSign(PrivateKeyManager key, String hashAlgorithm, String plainText) {
		/******** INPUT VERIFICATION - BEGIN ********/
		if(key == null)
		{
			error.setError("AE001", "Private key cannot be null");
			return "";
		}
		if(hashAlgorithm == null || hashAlgorithm.length() == 0 || SecurityUtils.compareStrings("", hashAlgorithm))
		{
			error.setError("AE002", "HashAlgorithm cannot be empty value; use HashAlgorithm domain");
			return "";
		}
		if(plainText == null || plainText.length() == 0 || SecurityUtils.compareStrings("", plainText))
		{
			error.setError("AE003", "The plainText value to sign cannot be empty");
			return "";
		}
		/******** INPUT VERIFICATION - END ********/
		
		
		EncodingUtil eu = new EncodingUtil();
		byte[] inputText = eu.getBytes(plainText);
		if (eu.hasError()) {
			this.error = eu.getError();
			return "";
		}
		String result = "";
		try(InputStream inputStream = new ByteArrayInputStream(inputText))
		{
			result = sign(key, hashAlgorithm, inputStream);
		}catch(Exception e)
		{
			error.setError("AE004", e.getMessage());
		}
		return result;
	}

	@Override
	public String doSignFile(PrivateKeyManager key, String hashAlgorithm, String path) {
		/******** INPUT VERIFICATION - BEGIN ********/
		if(key == null)
		{
			error.setError("AE005", "Private key cannot be null");
			return "";
		}
		if(hashAlgorithm == null || hashAlgorithm.length() == 0 || SecurityUtils.compareStrings("", hashAlgorithm))
		{
			error.setError("AE006", "HashAlgorithm cannot be empty value; use HashAlgorithm domain");
			return "";
		}
		if(path == null || path.length() == 0 || SecurityUtils.compareStrings("", path))
		{
			error.setError("AE007", "The path value of the file to sign cannot be empty");
			return "";
		}
		/******** INPUT VERIFICATION - END ********/
		
		String result = "";
		try(InputStream input = SecurityUtils.getFileStream(path, this.error))
		{
			if (this.hasError()) {
				return "";
			}
			
			result = sign(key, hashAlgorithm, input);
		}catch(Exception e)
		{
			error.setError("AE008", e.getMessage());
		}
		return result;
	}

	@Override
	public boolean doVerify(CertificateX509 cert, String plainText, String signature) {
		/******** INPUT VERIFICATION - BEGIN ********/
		if(cert == null)
		{
			error.setError("AE009", "Certificate cannot be null");
			return false;
		}
		if(plainText == null || plainText.length() == 0 || SecurityUtils.compareStrings("", plainText))
		{
			error.setError("AE010", "The plainText value to verify cannot be empty");
			return false;
		}
		if(signature == null || signature.length() == 0 || SecurityUtils.compareStrings("", signature))
		{
			error.setError("AE011", "The signature value to verify cannot be empty");
			return false;
		}
		/******** INPUT VERIFICATION - END ********/
		
		
		EncodingUtil eu = new EncodingUtil();
		byte[] inputText = eu.getBytes(plainText);
		if (eu.hasError()) {
			this.error = eu.getError();
			return false;
		}
		boolean result = false;
		try(InputStream inputStream = new ByteArrayInputStream(inputText))
		{
			result = verify(cert, inputStream, signature);
		}catch(Exception e)
		{
			error.setError("AE012", e.getMessage() );
		}
		return result;
	}

	@Override
	public boolean doVerifyFile(CertificateX509 cert, String path, String signature) {
		/******** INPUT VERIFICATION - BEGIN ********/
		if(cert == null)
		{
			error.setError("AE013", "Certificate cannot be null");
			return false;
		}
		if(path == null || path.length() == 0 || SecurityUtils.compareStrings("", path))
		{
			error.setError("AE014", "The path value of the faile to verify cannot be empty");
			return false;
		}
		if(signature == null || signature.length() == 0 || SecurityUtils.compareStrings("", signature))
		{
			error.setError("AE015", "The signature value to verify cannot be empty");
			return false;
		}
		/******** INPUT VERIFICATION - END ********/
		
		boolean result = false;
		try(InputStream input = SecurityUtils.getFileStream(path, this.error))
		{
			if (this.hasError()) {
				return false;
			}
			result = verify(cert, input, signature);
		}catch(Exception e)
		{
			error.setError("AE016", e.getMessage());
		}
		return result;
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

	private String sign(PrivateKey key, String hashAlgorithm, InputStream input) {
		PrivateKeyManager keyMan = (PrivateKeyManager) key;
		if (keyMan.hasError()) {
			this.error = keyMan.getError();
			return "";
		}
		AsymmetricSigningAlgorithm asymmetricSigningAlgorithm = AsymmetricSigningAlgorithm
				.getAsymmetricSigningAlgorithm(keyMan.getPrivateKeyAlgorithm(), this.error);
		if (this.hasError()) return "";
		Signer signer = AsymmetricSigningAlgorithm.getSigner(asymmetricSigningAlgorithm, getHash(hashAlgorithm),
				this.error);
		if (this.hasError()) return "";
		setUpSigner(signer, input, keyMan.getPrivateKeyParameterForSigning(), true);
		if (this.hasError()) return "";
		byte[] outputBytes = null;
		try {
			outputBytes = signer.generateSignature();
		} catch (Exception e) {
			error.setError("AE01", e.getMessage());
			return "";
		}
		String result = "";
		try {
			result = Base64.toBase64String(outputBytes);
		} catch (Exception e) {
			error.setError("AE018", e.getMessage());
			return "";
		}
		return result;
	}

	private boolean verify(Certificate certificate, InputStream input, String signature) {
		CertificateX509 cert = (CertificateX509) certificate;
		if (!cert.Inicialized() || cert.hasError()) {
			this.error = cert.getError();
			return false;
		}
		String hashAlgorithm = "";
		if (SecurityUtils.compareStrings(cert.getPublicKeyHash(), "ECDSA")) {
			hashAlgorithm = "SHA1";
		} else {
			hashAlgorithm = cert.getPublicKeyHash();
		}
		AsymmetricSigningAlgorithm asymmetricSigningAlgorithm = AsymmetricSigningAlgorithm
				.getAsymmetricSigningAlgorithm(cert.getPublicKeyAlgorithm(), this.error);
		if (this.hasError()) return false;
		Signer signer = AsymmetricSigningAlgorithm.getSigner(asymmetricSigningAlgorithm, getHash(hashAlgorithm),
				this.error);
		if (this.hasError()) return false;
		setUpSigner(signer, input, cert.getPublicKeyParameterForSigning(), false);
		if (this.hasError()) return false;
		byte[] signatureBytes = null;
		try {
			signatureBytes = Base64.decode(signature);
		} catch (Exception e) {
			error.setError("AE019", e.getMessage());
			return false;
		}

		if (signatureBytes == null || signatureBytes.length == 0) {
			this.error.setError("AE020", "Error reading signature");
			return false;
		}
		boolean result = false;
		try {
			result = signer.verifySignature(signatureBytes);
		} catch (Exception e) {
			error.setError("AE021", e.getMessage());
			return false;
		}
		return result;

	}

	private void setUpSigner(Signer signer, InputStream input, AsymmetricKeyParameter asymmetricKeyParameter,
			boolean toSign) {
		try {
			signer.init(toSign, asymmetricKeyParameter);
		} catch (Exception e) {
			error.setError("AE022", e.getMessage());
			return;
		}
		byte[] buffer = new byte[8192];
		int n;
		try {
			while ((n = input.read(buffer)) > 0) {
				signer.update(buffer, 0, n);
			}
		} catch (Exception e) {
			error.setError("AE023", e.getMessage());
			return;
		}
	}
	
	private Digest getHash(String hashAlgorithm) {
		HashAlgorithm hash = HashAlgorithm.getHashAlgorithm(hashAlgorithm, this.error);
		if (this.hasError()) {
			return null;
		}
		Hashing hashing = new Hashing();
		Digest digest = hashing.createHash(hash);
		if (hashing.hasError()) {
			this.error = hashing.getError();
			return null;
		}
		return digest;
	}
}
