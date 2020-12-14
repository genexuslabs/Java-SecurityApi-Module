package com.genexus.securityapicommons.keys;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.encoders.Base64;

import com.genexus.securityapicommons.utils.SecurityUtils;

public class CertificateX509 extends com.genexus.securityapicommons.commons.Certificate {

	private String publicKeyAlgorithm;
	private boolean hasPublicKey;
	private X509Certificate cert;
	public String issuer;
	public String subject;
	public String serialNumber;
	public String thumbprint;
	public Date notAfter;
	public Date notBefore;
	public int version;
	private SubjectPublicKeyInfo subjectPublicKeyInfo;
	private boolean inicialized;

	/**
	 * CertificateX509 class constructor
	 */
	public CertificateX509() {
		super();
		this.hasPublicKey = false;
		this.inicialized = false;
	}

	public boolean Inicialized() {
		return this.inicialized;
	}

	public X509Certificate Cert() {
		return this.cert;
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/
	@Override
	public boolean load(String path) {
		return loadPKCS12(path, "", "");
	}

	@Override
	public boolean loadPKCS12(String path, String alias, String password) {
		boolean result = false;
		try {
			result = loadPublicKeyFromFile(path, alias, password);
		} catch (Exception e) {
			this.error.setError("CE001", e.getMessage());
			return false;
		}
		if (result) {

			inicializeParameters();
		}
		return result;
	}

	@Override
	public boolean fromBase64(String base64Data) {
		boolean flag;
		try {
			byte[] dataBuffer = Base64.decode(base64Data);
			ByteArrayInputStream bI = new ByteArrayInputStream(dataBuffer);
			CertificateFactory cf = new CertificateFactory();
			this.cert = (X509Certificate) cf.engineGenerateCertificate(bI);
			inicializeParameters();
			flag = true;
		} catch (CertificateException e) {
			this.error.setError("CE002", "Error loading certificate from base64");
			flag = false;
		}
		if (flag) {

			inicializeParameters();
		}
		return flag;
	}

	@Override
	public String toBase64() {
		if (!this.inicialized) {
			this.error.setError("CE003", "Not loaded certificate");
			return "";
		}
		String base64Encoded = "";

		try {
			base64Encoded = new String(Base64.encode(this.cert.getEncoded()));

		} catch (Exception e) {
			this.error.setError("CE004", "Error encoding certificate to base64");
		}

		return base64Encoded;
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

	/**
	 * @return String certificate-s hash algorithm for sign verification
	 */
	public String getPublicKeyHash() {
		String[] aux = this.publicKeyAlgorithm.toUpperCase().split("WITH");
		if (SecurityUtils.compareStrings(aux[0], "1.2.840.10045.2.1")) {
			return "ECDSA";
		}
		return aux[0];
	}

	public AsymmetricKeyParameter getPublicKeyParameterForEncryption() {

		if (SecurityUtils.compareStrings(this.getPublicKeyAlgorithm(), "RSA")) {
			return getRSAKeyParameter();
		} else {

			this.error.setError("AE009", "Unrecognized encryption algorithm");
			return null;
		}
	}

	/**
	 * @return AsymmetricKeyParameter with loaded public key for RSA or ECDSA
	 *         signature verification
	 */
	public AsymmetricKeyParameter getPublicKeyParameterForSigning() {

		switch (this.getPublicKeyAlgorithm()) {
		case "RSA":
			return getRSAKeyParameter();
		case "ECDSA":
			AsymmetricKeyParameter parmsECDSA;
			try {
				parmsECDSA = PublicKeyFactory.createKey(this.subjectPublicKeyInfo);
			} catch (IOException e) {
				this.error.setError("AE010", "Not ECDSA key");
				e.printStackTrace();
				return null;
			}
			return parmsECDSA;
		default:
			this.error.setError("AE011", "Unrecognized signing algorithm");
			return null;
		}
	}

	private AsymmetricKeyParameter getRSAKeyParameter() {

		RSAKeyParameters parms;
		try {
			parms = (RSAKeyParameters) PublicKeyFactory.createKey(this.subjectPublicKeyInfo);
		} catch (IOException e) {
			this.error.setError("AE014", "Not RSA key");
			e.printStackTrace();
			return null;
		}
		return parms;
	}

	/**
	 * @return PublicKey type for the key type
	 */
	public PublicKey getPublicKeyXML() {
		KeyFactory kf = null;
		X509EncodedKeySpec encodedKeySpec = null;
		try {
			kf = SecurityUtils.getKeyFactory(this.getPublicKeyAlgorithm());
			encodedKeySpec = new X509EncodedKeySpec(this.subjectPublicKeyInfo.getEncoded());

		} catch (NoSuchAlgorithmException | IOException e) {
			this.error.setError("CE011", "Error reading algorithm");
		}
		PublicKey pk = null;
		if ((kf != null) && (encodedKeySpec != null)) {
			try {

				pk = kf.generatePublic(encodedKeySpec);
			} catch (InvalidKeySpecException e) {
				// e.printStackTrace();
				this.error.setError("CE010", "Error casting public key data for XML signing");
			}
		}
		return pk;

	}

	/**
	 * @return RSAPublicKey type for the key type
	 */
	public RSAPublicKey getRSAPublicKeyJWT() {
		KeyFactory kf = null;
		X509EncodedKeySpec encodedKeySpec = null;
		try {
			kf = SecurityUtils.getKeyFactory(this.getPublicKeyAlgorithm());
			encodedKeySpec = new X509EncodedKeySpec(this.subjectPublicKeyInfo.getEncoded());

		} catch (NoSuchAlgorithmException | IOException e) {
			this.error.setError("CE011", "Error reading algorithm");
		}
		RSAPublicKey pk = null;
		if ((kf != null) && (encodedKeySpec != null)) {
			try {

				pk = (RSAPublicKey) kf.generatePublic(encodedKeySpec);
			} catch (InvalidKeySpecException e) {
				// e.printStackTrace();
				this.error.setError("CE010", "Error casting public key data for XML signing");
			}
		}
		return pk;

	}

	/**
	 * stores SubjectPublicKeyInfo Data Type of public key from certificate,
	 * algorithm and digest
	 * 
	 * @param path     String of the certificate file
	 * @param alias    Srting certificate's alias, required if PKCS12
	 * @param password String certificate's password, required if PKCS12
	 * @return boolean true if loaded correctly
	 * @throws CertificateException
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 */
	private boolean loadPublicKeyFromFile(String path, String alias, String password)
			throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
		boolean result = false;
		if (SecurityUtils.extensionIs(path, ".pem")) {
			result = loadPublicKeyFromPEMFile(path);
			return result;
		}
		if (SecurityUtils.extensionIs(path, ".crt") || SecurityUtils.extensionIs(path, ".cer")) {
			result = loadPublicKeyFromDERFile(path);
			return result;
		}
		if (SecurityUtils.extensionIs(path, ".pfx") || SecurityUtils.extensionIs(path, ".p12")
				|| SecurityUtils.extensionIs(path, ".jks") || SecurityUtils.extensionIs(path, ".pkcs12")) {
			result = loadPublicKeyFromPKCS12File(path, alias, password);
			return result;
		}
		this.error.setError("CE005", "Error loading public key");
		this.hasPublicKey = false;
		return false;

	}

	/**
	 * stores SubjectPublicKeyInfo Data Type from certificate's public key,
	 * asymmetric algorithm and digest
	 * 
	 * @param path
	 * 
	 * 
	 * @param alias    Strting certificate's alias
	 * @param password String certificate's password
	 * @return boolean true if loaded correctly
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 */
	private boolean loadPublicKeyFromPKCS12File(String path, String alias, String password)
			throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {

		if (alias == null || password == null) {
			this.error.setError("CE012", "Alias and password are required for PKCS12 certificates");
			return false;
		}
		InputStream in;
		in = SecurityUtils.inputFileToStream(path);
		KeyStore ks;
		try {
			ks = KeyStore.getInstance("PKCS12");
			ks.load(in, password.toCharArray());
			this.cert = (X509Certificate) ks.getCertificate(alias);
		} catch (Exception e) {
			this.error.setError("CE013", path + "not found.");
			return false;
		}
		return true;

	}

	/**
	 * stores SubjectPublicKeyInfo Data Type from certificate's public key,
	 * asymmetric algorithm and digest
	 * 
	 * @param path String .pem certificate path
	 * @return boolean true if loaded correctly
	 * @throws IOException
	 * @throws CertificateException
	 */
	private boolean loadPublicKeyFromPEMFile(String path) throws IOException, CertificateException {
		boolean flag = false;
		FileReader privateKeyReader;
		privateKeyReader = new FileReader(new File(path));
		PEMParser parser = new PEMParser(privateKeyReader);
		Object obj;
		obj = parser.readObject();
		if (obj instanceof PrivateKeyInfo) {
			this.error.setError("CE007", "The file contains a private key");
			flag = false;
		}
		if ((obj instanceof PEMKeyPair) || (obj instanceof SubjectPublicKeyInfo)) {
			this.error.setError("CE008", "Invalid X509 Certificate format");
			flag = false;
		}
		if (obj instanceof X509CertificateHolder) {
			X509CertificateHolder x509 = (X509CertificateHolder) obj;
			CertificateFactory certFactory = new CertificateFactory();
			InputStream in;
			in = new ByteArrayInputStream(x509.getEncoded());
			this.cert = (X509Certificate) certFactory.engineGenerateCertificate(in);
			flag = true;
		}

		privateKeyReader.close();
		parser.close();
		if (!flag) {
			this.error.setError("CE016", "Error loading public key from pem file");
		}
		return flag;
	}

	/**
	 * stores PublicKeyInfo Data Type from the certificate's public key, asymmetric
	 * algorithm and digest
	 * 
	 * @param path String .crt .cer file certificate
	 * @return boolean true if loaded correctly
	 * @throws IOException
	 * @throws CertificateException
	 */
	private boolean loadPublicKeyFromDERFile(String path) throws IOException, CertificateException {
		InputStream input;
		input = SecurityUtils.inputFileToStream(path);
		CertificateFactory cf = new CertificateFactory();
		this.cert = (X509Certificate) cf.engineGenerateCertificate(input);
		input.close();
		return true;
	}

	private void inicializeParameters() {
		this.serialNumber = this.cert.getSerialNumber().toString();
		this.subject = this.cert.getSubjectDN().getName();
		this.version = this.cert.getVersion();
		this.issuer = this.cert.getIssuerDN().getName();
		this.thumbprint = "";
		this.notAfter = this.cert.getNotAfter();
		this.notBefore = this.cert.getNotBefore();
		this.publicKeyAlgorithm = this.cert.getSigAlgName();
		extractPublicInfo();
		this.inicialized = true;
	}

	/**
	 * Extract public key information and certificate's signing algorithm
	 * 
	 * @param cert java Certificate
	 */
	private void extractPublicInfo() {
		Certificate cert1 = (Certificate) this.cert;
		PublicKey publicKey = cert1.getPublicKey();
		this.subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
	}

	/**
	 * @return RSAPublicKey type for the key type
	 */
	public RSAPublicKey getRSAPublicKey() {
		KeyFactory kf = null;
		X509EncodedKeySpec encodedKeySpec = null;
		try {
			kf = SecurityUtils.getKeyFactory(this.getPublicKeyAlgorithm());
			encodedKeySpec = new X509EncodedKeySpec(this.subjectPublicKeyInfo.getEncoded());

		} catch (NoSuchAlgorithmException | IOException e) {
			this.error.setError("CE011", "Error reading algorithm");
		}
		RSAPublicKey pk = null;
		if ((kf != null) && (encodedKeySpec != null)) {
			try {

				pk = (RSAPublicKey) kf.generatePublic(encodedKeySpec);
			} catch (InvalidKeySpecException e) {
				// e.printStackTrace();
				this.error.setError("CE010", "Error casting public key data for XML signing");
			}
		}
		return pk;

	}

	/**
	 * @return String certificate-s asymmetric algorithm for sign verification
	 */
	public String getPublicKeyAlgorithm() {
		if (SecurityUtils.compareStrings(this.publicKeyAlgorithm, "1.2.840.10045.2.1")) {
			return "ECDSA";
		}
		String[] aux = this.publicKeyAlgorithm.toUpperCase().split("WITH");
		return aux[1];
	}
	
	/**
	 * @return ECPublicKey type for the key type
	 */
	public ECPublicKey getECPublicKeyJWT() {
		KeyFactory kf = null;
		X509EncodedKeySpec encodedKeySpec = null;
		try {
			kf = SecurityUtils.getKeyFactory(this.getPublicKeyAlgorithm());
			encodedKeySpec = new X509EncodedKeySpec(this.subjectPublicKeyInfo.getEncoded());

		} catch (NoSuchAlgorithmException | IOException e) {
			this.error.setError("CE017", "Error reading algorithm");
		}
		ECPublicKey pk = null;
		if ((kf != null) && (encodedKeySpec != null)) {
			try {

				pk = (ECPublicKey) kf.generatePublic(encodedKeySpec);
			} catch (InvalidKeySpecException e) {
				// e.printStackTrace();
				this.error.setError("CE018", "Error casting public key data for JWT signing");
			}
		}
		return pk;

	}



}
