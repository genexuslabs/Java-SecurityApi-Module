package com.genexus.cryptography.hash;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD128Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.RIPEMD256Digest;
import org.bouncycastle.crypto.digests.RIPEMD320Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;

import com.genexus.cryptography.commons.HashObject;
import com.genexus.cryptography.hash.utils.HashAlgorithm;
import com.genexus.securityapicommons.config.EncodingUtil;

public class Hashing extends HashObject {

	/**
	 * Hashing class constructor
	 */
	public Hashing() {
		super();
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/

	/**
	 * @param hashAlgorithm
	 *            String HashAlgorithm enum, algorithm name
	 * @param txtToHash
	 *            plain text to hcalculate hash
	 * @return String Hexa representation of the txtToHash with the algorithm
	 *         indicated
	 */
	public String doHash(String hashAlgorithm, String txtToHash) {
		this.error.cleanError();
		byte[] resBytes = calculateHash(HashAlgorithm.getHashAlgorithm(hashAlgorithm, this.error), txtToHash);
		String result = toHexaString(resBytes);
		if (!this.error.existsError()) {
			return result;
		}
		return "";
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

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

	/**
	 * @param hashAlgorithm
	 *            HashAlgorithm enum, algorithm name
	 * @param txtToHash
	 *            plain text to hcalculate hash
	 * @return byte array of the txtToHash with the algorithm indicated
	 */
	public byte[] calculateHash(HashAlgorithm hashAlgorithm, String txtToHash) {

		if (this.error.existsError()) {
			return null;
		}
		Digest alg = createHash(hashAlgorithm);
		EncodingUtil eu = new EncodingUtil();
		byte[] inputAsBytes = eu.getBytes(txtToHash);
		if (eu.getError().existsError()) {
			this.error = eu.getError();
			return null;
		}
		byte[] retValue = new byte[alg.getDigestSize()];
		alg.update(inputAsBytes, 0, inputAsBytes.length);
		alg.doFinal(retValue, 0);
		return retValue;
	}

	/**
	 * @param hashAlgorithm
	 *            HashAlgorithm enum, algorithm name
	 * @return Digest algorithm instantiated class
	 */
	public Digest createHash(HashAlgorithm hashAlgorithm) {
		switch (hashAlgorithm) {
		case MD5:
			return new MD5Digest();
		case SHA1:
			return new SHA1Digest();
		case SHA224:
			return new SHA224Digest();
		case SHA256:
			return new SHA256Digest();
		case SHA384:
			return new SHA384Digest();
		case SHA512:
			return new SHA512Digest();
		case BLAKE2B_224:
			return new Blake2bDigest(224);
		case BLAKE2B_256:
			return new Blake2bDigest(256);
		case BLAKE2B_384:
			return new Blake2bDigest(384);
		case BLAKE2B_512:
			return new Blake2bDigest(512);
		case BLAKE2S_128:
			return new Blake2sDigest(128);
		case BLAKE2S_160:
			return new Blake2sDigest(160);
		case BLAKE2S_224:
			return new Blake2sDigest(224);
		case BLAKE2S_256:
			return new Blake2sDigest(256);
		case GOST3411_2012_256:
			return new GOST3411_2012_256Digest();
		case GOST3411_2012_512:
			return new GOST3411_2012_512Digest();
		case GOST3411:
			return new GOST3411Digest();
		case KECCAK_224:
			return new KeccakDigest(224);
		case KECCAK_256:
			return new KeccakDigest(256);
		case KECCAK_288:
			return new KeccakDigest(288);
		case KECCAK_384:
			return new KeccakDigest(384);
		case KECCAK_512:
			return new KeccakDigest(512);
		case MD2:
			return new MD2Digest();
		case MD4:
			return new MD4Digest();
		case RIPEMD128:
			return new RIPEMD128Digest();
		case RIPEMD160:
			return new RIPEMD160Digest();
		case RIPEMD256:
			return new RIPEMD256Digest();
		case RIPEMD320:
			return new RIPEMD320Digest();
		case SHA3_224:
			return new SHA3Digest(224);
		case SHA3_256:
			return new SHA3Digest(256);
		case SHA3_384:
			return new SHA3Digest(384);
		case SHA3_512:
			return new SHA3Digest(512);
		case SHAKE_128:
			return new SHAKEDigest(128);
		case SHAKE_256:
			return new SHAKEDigest(256);
		case SM3:
			return new SM3Digest();
		case TIGER:
			return new TigerDigest();
		case WHIRLPOOL:
			return new WhirlpoolDigest();
		default:
			this.error.setError("HS002", "Unrecognized HashAlgorithm");
			return null;
		}
	}

}
