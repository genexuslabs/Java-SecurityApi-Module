package com.genexus.cryptography.mac;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

import com.genexus.cryptography.commons.CmacObject;
import com.genexus.cryptography.symmetric.SymmetricBlockCipher;
import com.genexus.cryptography.symmetric.utils.SymmetricBlockAlgorithm;
import com.genexus.securityapicommons.config.EncodingUtil;
import com.genexus.securityapicommons.utils.SecurityUtils;

public class Cmac extends CmacObject{

	public Cmac()
	{
		super();
	}

	
	/********EXTERNAL OBJECT PUBLIC METHODS  - BEGIN ********/

	@Override
	public String calculate(String plainText, String key, String algorithm, int macSize) {
		if(!isValidAlgorithm(algorithm))
		{
			this.error.setError("CM001", "Invalid Symmetric block algorithm for CMAC");
			return "";
		}
		SymmetricBlockAlgorithm symmetricBlockAlgorithm = SymmetricBlockAlgorithm.getSymmetricBlockAlgorithm(algorithm,
				this.error);
		SymmetricBlockCipher symCipher = new SymmetricBlockCipher();
		BlockCipher blockCipher = symCipher.getCipherEngine(symmetricBlockAlgorithm);
		if(symCipher.hasError()) {
			this.error = symCipher.getError();
			return "";
		}
		if(macSize>blockCipher.getBlockSize()*8)
		{
			this.error.setError("CM002", "The mac length must be less or equal than the algorithm block size.");
			return "";
		}
		byte[] byteKey = Hex.decode(key);
		EncodingUtil eu = new EncodingUtil();
		byte[] byteInput = eu.getBytes(plainText);
		
		CipherParameters params = new KeyParameter(byteKey);

		org.bouncycastle.crypto.macs.CMac mac = null;
		if(macSize!=0)
		{
			mac= new CMac(blockCipher,macSize );
		}else {
			mac= new CMac(blockCipher);
		}
		mac.init(params);
		byte[] resBytes = new byte[mac.getMacSize()];
		mac.update(byteInput, 0, byteInput.length);
		mac.doFinal(resBytes, 0);
		String result = toHexaString(resBytes);
		if (!this.error.existsError()) {
			return result;
		}
		return "";
		
	}

	@Override
	public boolean verify(String plainText, String key, String mac, String algorithm, int macSize) {
		String res = calculate(plainText, key, algorithm, macSize);
		return SecurityUtils.compareStrings(res, mac);
	}

	
	/********EXTERNAL OBJECT PUBLIC METHODS  - END ********/
	
	/**
	 * @param digest
	 *            byte array
	 * @return String Hexa respresentation of the byte array digest
	 */
	private String toHexaString(byte[] digest) {

		if (this.error.existsError()) {
			return "";
		}

		StringBuilder sb = new StringBuilder();
		for (byte b : digest) {
			sb.append(String.format("%02X ", b));
		}
		String result = sb.toString().replaceAll("\\s", "");
		if (result == null || result.length() == 0) {
			this.error.setError("HS001", "Error encoding hexa");
			return "";
		}
		return result.trim();

	}
	
	private boolean isValidAlgorithm(String algorithm) {
		SymmetricBlockAlgorithm symmetricBlockAlgorithm = SymmetricBlockAlgorithm.getSymmetricBlockAlgorithm(algorithm,
				this.error);
		int blockSize = SymmetricBlockAlgorithm.getBlockSize(symmetricBlockAlgorithm, this.error);
		if(this.hasError()) {
			
			return false;
		}
		if(blockSize != 64 && blockSize != 128)
		{
			
			return false;
		}
		
		return true;
	}
}
