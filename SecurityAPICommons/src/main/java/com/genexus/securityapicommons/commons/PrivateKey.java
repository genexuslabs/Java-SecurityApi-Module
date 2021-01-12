package com.genexus.securityapicommons.commons;

public abstract class PrivateKey extends Key{

	public PrivateKey() {
		super();
	}
	public abstract boolean load(String path);
	public abstract boolean loadPKCS12(String path, String alias, String password);
	public abstract boolean loadEncrypted(String privateKeyPath, String encryptionPassword);
	public abstract boolean fromBase64(String base64);
	public abstract String toBase64();
}
