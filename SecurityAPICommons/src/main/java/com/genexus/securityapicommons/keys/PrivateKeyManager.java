package com.genexus.securityapicommons.keys;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.EncryptedPrivateKeyInfo;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.util.encoders.Base64;

import com.genexus.securityapicommons.utils.SecurityUtils;

/**
 * @author sgrampone
 *
 */
public class PrivateKeyManager extends com.genexus.securityapicommons.commons.PrivateKey {

	private PrivateKeyInfo privateKeyInfo;
	private boolean hasPrivateKey;
	private String privateKeyAlgorithm;

	/**
	 * KeyManager class constructor
	 */
	public PrivateKeyManager() {
		super();
		this.hasPrivateKey = false;
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/
	@Override
	public boolean load(String privateKeyPath) {
		return loadPKCS12(privateKeyPath, "", "");
	}
	@Override
	public boolean loadPKCS12(String privateKeyPath, String alias, String password) {
		try {
			loadKeyFromFile(privateKeyPath, alias, password);
		} catch (Exception e) {
			this.error.setError("PK018", e.getMessage());
			return false;
		}
		if (this.hasError()) {
			return false;
		}
		return true;
	}
	
	@Override
	public boolean fromBase64(String base64)
	{
		boolean res;
		try {
			res = readBase64(base64);
		} catch (IOException e) {
			this.error.setError("PK0015", e.getMessage());
			return false;
		}
		this.hasPrivateKey = res;
		return res;
	}
	
	@Override
	public String toBase64()
	{
		if(this.hasPrivateKey) {
			String encoded = "";
			try {
				encoded =  Base64.toBase64String(this.privateKeyInfo.getEncoded());
			} catch (IOException e) {
				this.error.setError("PK0017", e.getMessage());
				return "";
			}
			return encoded;
		}
		this.error.setError("PK0016", "No private key loaded");
		return "";
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - END 
	 * @throws IOException ********/
	
	private boolean readBase64(String base64) throws IOException 
	{
		byte[] keybytes = Base64.decode(base64);
		ASN1InputStream istream = new ASN1InputStream(keybytes);
		ASN1Sequence seq = (ASN1Sequence) istream.readObject();
	    this.privateKeyInfo = PrivateKeyInfo.getInstance(seq);
	    istream.close();
	    if (this.privateKeyInfo == null)
	    {
	    	this.error.setError("PK015", "Could not read private key from base64 string");
	    	return false;
	    }
	    this.privateKeyAlgorithm = this.privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm().getId(); // 1.2.840.113549.1.1.1
	    return true;
	}
	
	/**
	 * @return PrivateKey type for the key type
	 */
	public PrivateKey getPrivateKeyXML() {

		KeyFactory kf = null;
		PKCS8EncodedKeySpec keySpec = null;
		try {
			kf = SecurityUtils.getKeyFactory(this.getPrivateKeyAlgorithm());
			keySpec = new PKCS8EncodedKeySpec(this.privateKeyInfo.getEncoded());

		} catch (NoSuchAlgorithmException | IOException e) {
			this.error.setError("PK001", "Error reading algorithm");
		}
		PrivateKey pk = null;
		if ((kf != null) && (keySpec != null)) {
			try {
				pk = kf.generatePrivate(keySpec);
			} catch (InvalidKeySpecException e) {
				this.error.setError("PK002", "Error reading key");
			}
		}
		return pk;

	}
	

	/**
	 * @return PrivateKey type for the key type
	 */
	public RSAPrivateKey getRSAPrivateKeyJWT() {

		KeyFactory kf = null;
		PKCS8EncodedKeySpec keySpec = null;
		try {
			kf = SecurityUtils.getKeyFactory(this.getPrivateKeyAlgorithm());
			keySpec = new PKCS8EncodedKeySpec(this.privateKeyInfo.getEncoded());

		} catch (NoSuchAlgorithmException | IOException e) {
			this.error.setError("PK001", "Error reading algorithm");
		}
		RSAPrivateKey pk = null;
		if ((kf != null) && (keySpec != null)) {
			try {
				pk = (RSAPrivateKey) kf.generatePrivate(keySpec);
			} catch (InvalidKeySpecException e) {
				this.error.setError("PK002", "Error reading key");
			}
		}
		return pk;

	}
	
	/**
	 * Return AsymmetricKeyParameter with private key for the indicated algorithm
	 * 
	 * @param asymmetricEncryptionAlgorithm
	 *            AsymmetricEncryptionAlgorithm enum, algorithm name
	 * @return AsymmetricKeyParameter type for encryption, algorithm dependant
	 */
	public AsymmetricKeyParameter getPrivateKeyParameterForEncryption() {
		
		if(SecurityUtils.compareStrings(this.getPrivateKeyAlgorithm(), "RSA")){
			return getRSAKeyParameter();
		}else {
	
			this.error.setError("AE009", "Unrecognized encryption algorithm");
			return null;
		}
	}
	
	/**
	 * @return AsymmetricKeyParameter with private key loaded for RSA or ECDSA for
	 *         signing
	 */
	public AsymmetricKeyParameter getPrivateKeyParameterForSigning() {
		switch (this.getPrivateKeyAlgorithm()) {
		case "RSA":
			return getRSAKeyParameter();
		case "ECDSA":
			AsymmetricKeyParameter parmsECDSA;
			try {
				parmsECDSA = PrivateKeyFactory.createKey(this.privateKeyInfo);
			} catch (IOException e) {
				this.error.setError("AE007", "Not ECDSA key");
				e.printStackTrace();
				return null;
			}
			return parmsECDSA;
		default:
			this.error.setError("AE008", "Unrecognized algorithm");
			return null;
		}
	}
	
	/**
	 * @return AsymmetricKeyParameter for RSA with loaded key
	 */
	private AsymmetricKeyParameter getRSAKeyParameter() {
		RSAKeyParameters parms;
			try {
				parms = (RSAKeyParameters) PrivateKeyFactory.createKey(this.privateKeyInfo);
			} catch (IOException e) {
				this.error.setError("AE013", "Not RSA key");
				e.printStackTrace();
				return null;
			}
		return parms;
	}

	/**
	 * @return String certificate's algorithm for signing, 1.2.840.113549.1.1.1 if
	 *         RSA from key pem file
	 *         https://www.alvestrand.no/objectid/1.2.840.113549.1.1.1.html
	 */
	public String getPrivateKeyAlgorithm() {
		if (SecurityUtils.compareStrings(this.privateKeyAlgorithm, "1.2.840.113549.1.1.1")
				|| SecurityUtils.compareStrings(this.privateKeyAlgorithm, "RSA")) {
			return "RSA";
		}
		if (SecurityUtils.compareStrings(this.privateKeyAlgorithm, "1.2.840.10045.2.1")
				|| SecurityUtils.compareStrings(this.privateKeyAlgorithm, "EC")) {
			return "ECDSA";
		}
		return this.privateKeyAlgorithm.toUpperCase();

	}

	/**
	 * @return boolean true if private key is stored
	 */
	public boolean hasPrivateKey() {
		return this.hasPrivateKey;
	}

	/**
	 * Stores structure of public or private key from any type of certificate
	 * 
	 * @param path
	 *            String of the certificate file
	 * @param alias
	 *            Srting certificate's alias, required if PKCS12
	 * @param password
	 *            String certificate's password, required if PKCS12
	 * @return boolean true if loaded correctly
	 * @throws CertificateException
	 * @throws IOException
	 * @throws UnrecoverableKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 */
	private boolean loadKeyFromFile(String path, String alias, String password) throws CertificateException,
			IOException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
		return loadPrivateKeyFromFile(path, alias, password);
	}

	/**
	 * Stores PrivateKeyInfo Data Type from certificate's private key, algorithm and
	 * digest
	 * 
	 * @param path
	 *            String of the certificate file
	 * @param alias
	 *            Srting certificate's alias, required if PKCS12
	 * @param password
	 *            String certificate's password, required if PKCS12
	 * @return boolean true if loaded correctly
	 * @throws CertificateException
	 * @throws IOException
	 * @throws UnrecoverableKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 */
	private boolean loadPrivateKeyFromFile(String path, String alias, String password) throws CertificateException,
			IOException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
		if (SecurityUtils.extensionIs(path, ".pem") || SecurityUtils.extensionIs(path, ".key")) {
			return this.hasPrivateKey = loadPrivateKeyFromPEMFile(path);
		}
		if (SecurityUtils.extensionIs(path, ".pfx") || SecurityUtils.extensionIs(path, ".p12")
				|| SecurityUtils.extensionIs(path, ".jks") || SecurityUtils.extensionIs(path, ".pkcs12")) {
			return this.hasPrivateKey = loadPrivateKeyFromPKCS12File(path, alias, password);
		}
		this.error.setError("PK014", "Error loading private key");
		this.hasPrivateKey = false;
		return false;
	}

	/**
	 * Stores PrivateKeyInfo Data Type from the certificate's private key, algorithm
	 * and digest
	 * 
	 * @param path
	 *            String .ps12, pfx or .jks (PKCS12 fromat) certificate path
	 * @param alias
	 *            String certificate's alias
	 * @param password
	 *            String certificate's password
	 * @return boolean true if loaded correctly
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws UnrecoverableKeyException
	 * @throws KeyStoreException
	 */
	private boolean loadPrivateKeyFromPKCS12File(String path, String alias, String password) throws IOException,
			NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, KeyStoreException {

		if (alias == null || password == null) {
			this.error.setError("PK004", "Alias and Password are required for PKCS12 keys");
			return false;
		}
		InputStream in = SecurityUtils.inputFileToStream(path);
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(in, password.toCharArray());
		if (ks.getKey(alias, password.toCharArray()) != null) {
			PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
			this.privateKeyAlgorithm = privateKey.getAlgorithm();
			this.privateKeyInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
			return true;
		}

		return false;

	}

	/**
	 * stores PrivateKeyInfo Data Type from certificate's private key
	 * 
	 * @param path
	 *            String .pem certificate path
	 * @return boolean true if loaded correctly
	 * @throws IOException
	 * @throws CertificateException
	 */
	private boolean loadPrivateKeyFromPEMFile(String path) throws IOException, CertificateException {
		boolean flag = false;
		FileReader privateKeyReader;

		privateKeyReader = new FileReader(new File(path));
		PEMParser parser = new PEMParser(privateKeyReader);
		Object obj;
		obj = parser.readObject();
		if (obj instanceof EncryptedPrivateKeyInfo) {
			this.error.setError("PK007", "Encrypted key, remove the key password");
			flag = false;
		}
		if (obj instanceof PrivateKeyInfo) {
			this.privateKeyInfo = (PrivateKeyInfo) obj;
			this.privateKeyAlgorithm = this.privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm().getId(); // 1.2.840.113549.1.1.1
			flag = true;
		}
		if (obj instanceof PEMKeyPair) {
			PEMKeyPair pemKeyPair = (PEMKeyPair) obj;
			this.privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
			this.privateKeyAlgorithm = this.privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm().getId(); // 1.2.840.113549.1.1.1
			flag = true;
		}
		if (obj instanceof SubjectPublicKeyInfo) {
			this.error.setError("PK008", "The file contains a public key");
			flag = false;
		}
		if (obj instanceof X509CertificateHolder) {
			this.error.setError("PK009", "The file contains a public key");
			flag = false;
		}
		if (obj instanceof PKCS8EncryptedPrivateKeyInfo) {
			this.error.setError("PK010", "Encrypted key, remove the key password");
			flag = false;
		}
		privateKeyReader.close();
		parser.close();
		if (!flag) {
			if (!this.hasError()) {
				this.error.setError("PK011", "Error loading private key from pem file");
			}
		}
		return flag;
	}

}
