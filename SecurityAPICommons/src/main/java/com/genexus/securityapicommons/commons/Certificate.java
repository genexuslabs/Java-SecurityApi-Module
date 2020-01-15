package com.genexus.securityapicommons.commons;

public abstract class Certificate extends PrivateKey {

	public Certificate() {
		super();
	}


	public abstract boolean fromBase64(String base64Data);

	public abstract String toBase64();
}
