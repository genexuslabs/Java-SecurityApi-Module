package com.genexus.cryptography.passwordDerivation;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.BCrypt;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import com.genexus.cryptography.commons.PasswordDerivationObject;
import com.genexus.securityapicommons.config.EncodingUtil;
import com.genexus.securityapicommons.encoders.HexaEncoder;

/**
 * @author sgrampone
 *
 */
public class PasswordDerivation extends PasswordDerivationObject {

	/**
	 * PasswordDerivation class constructor
	 */
	public PasswordDerivation() {
		super();
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/

	/**
	 * @param password
	 *            String UTF-8 to hash
	 * @param salt
	 *            String UTF-8 to use as salt
	 * @param CPUCost
	 *            CPUCost must be larger than 1, a power of 2 and less than 2^(128 *
	 *            blockSize / 8)
	 * @param blockSize
	 *            The blockSize must be >= 1
	 * @param parallelization
	 *            Parallelization must be a positive integer less than or equal to
	 *            Integer.MAX_VALUE / (128 * blockSize * 8)
	 * @param keyLenght
	 *            fixed key length
	 */
	public String doGenerateSCrypt(String password, String salt, int CPUCost, int blockSize, int parallelization,
			int keyLenght) {
		this.error.cleanError();
		if (!areSCRyptValidParameters(CPUCost, blockSize, parallelization)) {
			return "";
		}
		EncodingUtil eu = new EncodingUtil();
		if (eu.getError().existsError()) {
			this.error = eu.getError();
			return "";
		}
		byte[] encryptedBytes = SCrypt.generate(eu.getBytes(password), eu.getBytes(salt), CPUCost, blockSize,
				parallelization, keyLenght);
		String result = Strings.fromByteArray(Base64.encode(encryptedBytes));
		if (result == null || result.length() == 0) {
			this.error.setError("PD009", "SCrypt generation error");
			return "";
		}
		this.error.cleanError();
		return result;
	}

	/**
	 * 
	 * Calculates SCrypt digest with arbitrary fixed parameters: CPUCost (N) = 16384
	 * blockSize (r) = 8 parallelization (p) = 1 keyLenght = 256
	 * 
	 * @param password
	 *            String UTF-8 to hash
	 * @param salt
	 *            String UTF-8 to use as salt
	 */
	public String doGenerateDefaultSCrypt(String password, String salt) {
		int N = 16384;
		int r = 8;
		int p = 1;
		int keyLenght = 256;
		return doGenerateSCrypt(password, salt, N, r, p, keyLenght);
	}

	/**
	 * @param password
	 *            String UTF-8 to hash. the password bytes (up to 72 bytes) to use
	 *            for this invocation.
	 * @param salt
	 *            String hexa to salt. The salt lenght must be 128 bits
	 * @param cost
	 *            The cost of the bcrypt function grows as 2^cost. Legal values are
	 *            4..31 inclusive.
	 * @return String Base64 hashed password to store
	 */
	public String doGenerateBcrypt(String password, String salt, int cost) {
		this.error.cleanError();
		if (!areBCryptValidParameters(password, salt, cost)) {
			return "";
		}
		EncodingUtil eu = new EncodingUtil();
		HexaEncoder hexa = new HexaEncoder();
		byte[] encryptedBytes = BCrypt.generate(eu.getBytes(password), Strings.toByteArray(hexa.fromHexa(salt)), cost);
		String result = Strings.fromByteArray(Base64.encode(encryptedBytes));
		if (result == null || result.length() == 0) {
			this.error.setError("PD010", "Bcrypt generation error");
			return "";
		}
		this.error.cleanError();
		return result;
	}

	/**
	 * Calculates Bcrypt digest with arbitrary fixed cost parameter: cost = 6
	 * 
	 * @param password
	 *            String UTF-8 to hash. the password bytes (up to 72 bytes) to use
	 *            for this invocation.
	 * @param salt
	 *            String UTF-8 to salt. The salt lenght must be 128 bits
	 * @return String Base64 hashed password to store
	 */
	public String doGenerateDefaultBcrypt(String password, String salt) {
		int cost = 6;
		return doGenerateBcrypt(password, salt, cost);
	}

	public String doGenerateArgon2(String argon2Version10, String argon2HashType, int iterations, int memory,
			int parallelism, String password, String salt, int hashLength) {
		if (!areArgon2ValidParameters(iterations, parallelism, hashLength)) {
			return "";
		}
		Argon2Version ver_aux = Argon2Version.getArgon2Version(argon2Version10, this.error);
		int version = Argon2Version.getVersionParameter(ver_aux, this.error);
		if (this.hasError()) {
			return "";
		}
		Argon2HashType hash_aux = Argon2HashType.getArgon2HashType(argon2HashType, this.error);
		int hashType = Argon2HashType.getArgon2Parameter(hash_aux, this.error);
		if (this.hasError()) {
			return "";
		}

		EncodingUtil eu = new EncodingUtil();
		HexaEncoder hexa = new HexaEncoder();
		byte[] bytePass = eu.getBytes(password);
		if(eu.hasError())
		{
			this.error = eu.getError();
			return "";
		}

		Argon2Parameters.Builder builder = new Argon2Parameters.Builder(hashType).withVersion(version)
				.withIterations(iterations).withMemoryPowOfTwo(memory).withParallelism(parallelism)
				.withSalt(Strings.toByteArray(hexa.fromHexa(salt)));

		Argon2BytesGenerator dig = new Argon2BytesGenerator();
		dig.init(builder.build());
		byte[] res = new byte[hashLength];
		dig.generateBytes(bytePass, res);
		String result = Strings.fromByteArray(Base64.encode(res));
		if (result == null || result.length() == 0) {
			this.error.setError("PD012", "Argon2 generation error");
			return "";
		}
		this.error.cleanError();
		return result;

	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

	/**
	 * @param pwd
	 *            password String UTF-8 to hash. the password bytes (up to 72 bytes)
	 *            to use for this invocation.
	 * @param salt
	 *            salt String UTF-8 to salt. The salt lenght must be 128 bits
	 * @param cost
	 *            cost The cost of the bcrypt function grows as 2^cost. Legal values
	 *            are 4..31 inclusive.
	 * @return true if BCrypt parameters are correct
	 */
	private boolean areBCryptValidParameters(String pwd, String salt, int cost) {
		EncodingUtil eu = new EncodingUtil();
		HexaEncoder hexa = new HexaEncoder();
		byte[] pwdBytes = eu.getBytes(pwd);
		byte[] saltBytes = Strings.toByteArray(hexa.fromHexa(salt));
		if (saltBytes.length * 8 != 128) {
			this.error.setError("PD008", "The salt lenght must be 128 bits");
			return false;
		}
		if (cost < 4 || cost > 31) {
			this.error.setError("PD007",
					"The cost of the bcrypt function grows as 2^cost. Legal values are 4..31 inclusive.");
			return false;
		}
		if (pwdBytes.length > 72) {
			this.error.setError("PD006", "The password bytes (up to 72 bytes) to use for this invocation.");
			return false;
		}
		return true;
	}

	/**
	 * @param number
	 *            int number to test
	 * @return true if number is power of 2
	 */
	private static boolean isPowerOfTwo(int number) {
		return number > 0 && ((number & (number - 1)) == 0);
	}

	/**
	 * @param CPUCost
	 *            CPUCost must be larger than 1, a power of 2 and less than 2^(128 *
	 *            blockSize / 8)
	 * @param blockSize
	 *            The blockSize must be >= 1
	 * @param parallelization
	 *            Parallelization must be a positive integer less than or equal to
	 *            Integer.MAX_VALUE / (128 * blockSize * 8)
	 * @return true if SCrypt parameters are correct
	 */
	private boolean areSCRyptValidParameters(int CPUCost, int blockSize, int parallelization) {
		if (blockSize < 1) {
			this.error.setError("PD005", "The blockSize must be >= 1");
			return false;
		}
		if (CPUCost < 2 || CPUCost >= Math.pow(2, 128 * blockSize / 8) || !isPowerOfTwo(CPUCost)) {
			this.error.setError("PD004",
					"CPUCost must be larger than 1, a power of 2 and less than 2^(128 * blockSize / 8)");
			return false;
		}
		if (parallelization <= 0 || parallelization > Integer.MAX_VALUE / (128 * blockSize * 8)) {
			this.error.setError("PD003",
					"Parallelization must be a positive integer less than or equal to Integer.MAX_VALUE / (128 * blockSize * 8)");
			return false;
		}
		return true;
	}

	private boolean areArgon2ValidParameters(int iterations, int parallelism, int hashLength) {
		if (parallelism < 1 || parallelism >= 16777216) {
			this.error.setError("PD012", "Parallelism parameter must be >= 1 and < 16777216");
			return false;
		}
		if (iterations < 1) {
			this.error.setError("PD013", "Must be 1 iteration at least");
			return false;
		}
		if (hashLength < 4) {
			this.error.setError("PD014", "The output hash length must be >= 4");
			return false;
		}
		return true;
	}
}
