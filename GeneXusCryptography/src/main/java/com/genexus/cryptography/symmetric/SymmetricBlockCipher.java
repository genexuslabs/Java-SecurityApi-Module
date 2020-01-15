package com.genexus.cryptography.symmetric;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.engines.CAST5Engine;
import org.bouncycastle.crypto.engines.CAST6Engine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.engines.NoekeonEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.engines.RC532Engine;
import org.bouncycastle.crypto.engines.RC564Engine;
import org.bouncycastle.crypto.engines.RC6Engine;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.engines.SkipjackEngine;
import org.bouncycastle.crypto.engines.TEAEngine;
import org.bouncycastle.crypto.engines.ThreefishEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.engines.XTEAEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.CTSBlockCipher;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GOFBBlockCipher;
import org.bouncycastle.crypto.modes.KCCMBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.modes.OpenPGPCFBBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.ISO10126d2Padding;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.X923Padding;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import com.genexus.cryptography.commons.SymmetricBlockCipherObject;
import com.genexus.cryptography.symmetric.utils.SymmetricBlockAlgorithm;
import com.genexus.cryptography.symmetric.utils.SymmetricBlockMode;
import com.genexus.cryptography.symmetric.utils.SymmetricBlockPadding;
import com.genexus.securityapicommons.config.AvailableEncoding;
import com.genexus.securityapicommons.config.EncodingUtil;
import com.genexus.securityapicommons.utils.SecurityUtils;

/**
 * @author sgrampone
 *
 */
public class SymmetricBlockCipher extends SymmetricBlockCipherObject {

	/**
	 * SymmetricBlockCipher class constructor
	 */
	public SymmetricBlockCipher() {
		super();
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/

	/**
	 * @param symmetricBlockAlgorithm
	 *            String SymmetricBlockAlgorithm enum, symmetric block algorithm
	 *            name
	 * @param symmetricBlockMode
	 *            String SymmetricBlockModes enum, symmetric block mode name
	 * @param key
	 *            String Hexa key for the algorithm excecution
	 * @param macSize
	 *            int macSize in bits for MAC length for AEAD Encryption algorithm
	 * @param nonce
	 *            String Hexa nonce for MAC length for AEAD Encryption algorithm
	 * @param plainText
	 *            String UTF-8 plain text to encrypt
	 * @return String Base64 encrypted text with the given algorithm and parameters
	 */
	public String doAEADEncrypt(String symmetricBlockAlgorithm, String symmetricBlockMode, String key, int macSize,
			String nonce, String plainText) {
		this.error.cleanError();
		SymmetricBlockAlgorithm algorithm = SymmetricBlockAlgorithm.getSymmetricBlockAlgorithm(symmetricBlockAlgorithm,
				this.error);
		SymmetricBlockMode mode = SymmetricBlockMode.getSymmetricBlockMode(symmetricBlockMode, this.error);
		if (this.error.existsError()) {
			return "";
		}
		BlockCipher engine = getCipherEngine(algorithm);
		AEADBlockCipher bbc = getAEADCipherMode(engine, mode);
		if (this.error.existsError() && !(this.error.getCode().compareToIgnoreCase("SB016") == 0)) {
			return "";
		}
		KeyParameter keyParam = new KeyParameter(Hex.decode(key));
		byte[] nonceBytes = Hex.decode(nonce);
		AEADParameters AEADparams = new AEADParameters(keyParam, macSize, nonceBytes);
		bbc.init(true, AEADparams);
		EncodingUtil eu = new EncodingUtil();
		byte[] inputBytes = eu.getBytes(plainText);
		if (eu.getError().existsError()) {
			this.error = eu.getError();
			return "";
		}
		byte[] outputBytes = new byte[bbc.getOutputSize(inputBytes.length)];
		int length = bbc.processBytes(inputBytes, 0, inputBytes.length, outputBytes, 0);
		try {
			bbc.doFinal(outputBytes, length);
		} catch (DataLengthException | IllegalStateException | InvalidCipherTextException e) {
			this.error.setError("SB010", "AEAD encryption exception");
			e.printStackTrace();
		}
		String result = new String(Base64.encode(outputBytes));
		if (result == null || result.length() == 0) {
			this.error.setError("SB011", "Error encoding base64");
			return "";
		}
		this.error.cleanError();
		return result.trim();
	}

	/**
	 * @param symmetricBlockAlgorithm
	 *            String SymmetricBlockAlgorithm enum, symmetric block algorithm
	 *            name
	 * @param symmetricBlockMode
	 *            String SymmetricBlockModes enum, symmetric block mode name
	 * @param key
	 *            String Hexa key for the algorithm excecution
	 * @param macSize
	 *            int macSize in bits for MAC length for AEAD Encryption algorithm
	 * @param nonce
	 *            String Hexa nonce for MAC length for AEAD Encryption algorithm
	 * @param encryptedInput
	 *            String Base64 text to decrypt
	 * @return String plain text UTF-8 with the given algorithm and parameters
	 */
	public String doAEADDecrypt(String symmetricBlockAlgorithm, String symmetricBlockMode, String key, int macSize,
			String nonce, String encryptedInput) {
		this.error.cleanError();
		SymmetricBlockAlgorithm algorithm = SymmetricBlockAlgorithm.getSymmetricBlockAlgorithm(symmetricBlockAlgorithm,
				this.error);
		SymmetricBlockMode mode = SymmetricBlockMode.getSymmetricBlockMode(symmetricBlockMode, this.error);
		if (this.error.existsError()) {
			return "";
		}
		BlockCipher engine = getCipherEngine(algorithm);
		AEADBlockCipher bbc = getAEADCipherMode(engine, mode);
		if (this.error.existsError() && !(this.error.getCode().compareToIgnoreCase("SB016") == 0)) {
			return "";
		}
		KeyParameter keyParam = new KeyParameter(Hex.decode(key));
		byte[] nonceBytes = Hex.decode(nonce);
		AEADParameters AEADparams = new AEADParameters(keyParam, macSize, nonceBytes);
		bbc.init(false, AEADparams);
		byte[] out2 = Base64.decode(encryptedInput);
		byte[] comparisonBytes = new byte[bbc.getOutputSize(out2.length)];
		int length = bbc.processBytes(out2, 0, out2.length, comparisonBytes, 0);
		try {
			bbc.doFinal(comparisonBytes, length);
		} catch (DataLengthException | IllegalStateException | InvalidCipherTextException e) {
			this.error.setError("SB012", "AEAD decryption exception");
			e.printStackTrace();
		}
		EncodingUtil eu = new EncodingUtil();
		String result = eu.getString(comparisonBytes);
		if (eu.getError().existsError()) {
			this.error = eu.getError();
			return "";
		}
		this.error.cleanError();
		return result.trim();

	}

	/**
	 * @param symmetricBlockAlgorithm
	 *            String SymmetricBlockAlgorithm enum, symmetric block algorithm
	 *            name
	 * @param symmetricBlockMode
	 *            String SymmetricBlockModes enum, symmetric block mode name
	 * @param symmetricBlockPadding
	 *            String SymmetricBlockPadding enum, symmetric block padding name
	 * @param key
	 *            String Hexa key for the algorithm excecution
	 * @param IV
	 *            String IV for the algorithm execution, must be the same length as
	 *            the blockSize
	 * @param plainText
	 *            String UTF-8 plain text to encrypt
	 * @return String Base64 encrypted text with the given algorithm and parameters
	 */
	public String doEncrypt(String symmetricBlockAlgorithm, String symmetricBlockMode, String symmetricBlockPadding,
			String key, String IV, String plainText) {
		this.error.cleanError();
		SymmetricBlockAlgorithm algorithm = SymmetricBlockAlgorithm.getSymmetricBlockAlgorithm(symmetricBlockAlgorithm,
				this.error);
		SymmetricBlockMode mode = SymmetricBlockMode.getSymmetricBlockMode(symmetricBlockMode, this.error);
		SymmetricBlockPadding padding = SymmetricBlockPadding.getSymmetricBlockPadding(symmetricBlockPadding,
				this.error);

		if (this.error.existsError()) {
			return "";
		}
		BufferedBlockCipher bbc = getCipher(algorithm, mode, padding);
		if (this.error.existsError() && !(this.error.getCode().compareToIgnoreCase("SB016") == 0)) {
			return "";
		}
		byte[] byteIV = Hex.decode(IV);
		byte[] byteKey = Hex.decode(key);
		KeyParameter keyParam = new KeyParameter(byteKey);

		if (SymmetricBlockMode.ECB != mode && SymmetricBlockMode.OPENPGPCFB != mode) {
			ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, byteIV);
			bbc.init(true, keyParamWithIV);
		} else {
			bbc.init(true, keyParam);
		}
		EncodingUtil eu = new EncodingUtil();
		byte[] inputBytes = eu.getBytes(plainText);// plainText.getBytes();
		if (eu.hasError()) {
			this.error = eu.getError();
			return "";
		}
		byte[] outputBytes = new byte[bbc.getOutputSize(inputBytes.length)];
		int length = bbc.processBytes(inputBytes, 0, inputBytes.length, outputBytes, 0);
		try {
			bbc.doFinal(outputBytes, length);
		} catch (DataLengthException | IllegalStateException | InvalidCipherTextException e) {
			this.error.setError("SB013", "Block encryption exception");
			e.printStackTrace();
		}
		String result = new String(Base64.encode(outputBytes));
		if (result == null || result.length() == 0) {
			this.error.setError("SB014", "Error encoding base64");
			return "";
		}
		this.error.cleanError();
		return result.trim();
	}

	/**
	 * @param symmetricBlockAlgorithm
	 *            String SymmetricBlockAlgorithm enum, symmetric block algorithm
	 *            name
	 * @param symmetricBlockMode
	 *            String SymmetricBlockModes enum, symmetric block mode name
	 * @param symmetricBlockPadding
	 *            String SymmetricBlockPadding enum, symmetric block padding name
	 * @param key
	 *            String Hexa key for the algorithm excecution
	 * @param IV
	 *            String IV for the algorithm execution, must be the same length as
	 *            the blockSize
	 * @param encryptedInput
	 *            String Base64 text to decrypt
	 * @return String plain text UTF-8 with the given algorithm and parameters
	 */
	public String doDecrypt(String symmetricBlockAlgorithm, String symmetricBlockMode, String symmetricBlockPadding,
			String key, String IV, String encryptedInput) {
		this.error.cleanError();
		SymmetricBlockAlgorithm algorithm = SymmetricBlockAlgorithm.getSymmetricBlockAlgorithm(symmetricBlockAlgorithm,
				this.error);
		SymmetricBlockMode mode = SymmetricBlockMode.getSymmetricBlockMode(symmetricBlockMode, this.error);
		SymmetricBlockPadding padding = SymmetricBlockPadding.getSymmetricBlockPadding(symmetricBlockPadding,
				this.error);
		if (this.error.existsError()) {
			return "";
		}
		BufferedBlockCipher bbc = getCipher(algorithm, mode, padding);
		if (this.error.existsError() && !(this.error.getCode().compareToIgnoreCase("SB016") == 0)) {
			return "";
		}
		byte[] bytesKey = Hex.decode(key);
		byte[] bytesIV = Hex.decode(IV);
		KeyParameter keyParam = new KeyParameter(bytesKey);
		if (SymmetricBlockMode.ECB != mode && SymmetricBlockMode.OPENPGPCFB != mode) {
			ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, bytesIV);
			bbc.init(false, keyParamWithIV);
		} else {
			bbc.init(false, keyParam);
		}

		byte[] out2 = Base64.decode(encryptedInput);
		byte[] comparisonBytes = new byte[bbc.getOutputSize(out2.length)];
		int length = bbc.processBytes(out2, 0, out2.length, comparisonBytes, 0);
		try {
			bbc.doFinal(comparisonBytes, length);
		} catch (DataLengthException | IllegalStateException | InvalidCipherTextException e) {
			this.error.setError("SB015", "Block decryption exception");
			e.printStackTrace();
		}
		EncodingUtil eu = new EncodingUtil();
		String result = eu.getString(comparisonBytes);
		if (eu.getError().existsError()) {
			this.error = eu.getError();
			return "";
		}
		this.error.cleanError();
		return result.trim();
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

	/**
	 * Gets the BufferedBlockCipher loaded with Padding, Mode and Engine to Encrypt
	 * with a Symmetric Block Algorithm
	 * 
	 * @param algorithm
	 *            SymmetricBlockAlgorithm enum, algorithm name
	 * @param mode
	 *            SymmetricBlockModes enum, mode name
	 * @param padding
	 *            SymmetricBlockPadding enum, padding name
	 * @return BufferedBlockCipher loaded with Padding, Mode and Engine to Encrypt
	 *         with a Symmetric Block Algorithm
	 */
	private BufferedBlockCipher getCipher(SymmetricBlockAlgorithm algorithm, SymmetricBlockMode mode,
			SymmetricBlockPadding padding) {
		BlockCipher engine = getCipherEngine(algorithm);
		BlockCipherPadding paddingCipher = getPadding(padding);
		BlockCipher bc;
		if (mode != SymmetricBlockMode.ECB) {
			bc = getCipherMode(engine, mode);
		} else {
			bc = engine;
		}
		// si el padding es WITHCTS el paddingCipher es null
		if (usesCTS(mode, padding)) {
			return new CTSBlockCipher(bc); // no usa el paddingCipher que es el null
		}
		if (padding == SymmetricBlockPadding.NOPADDING) {
			return new BufferedBlockCipher(bc);
		} else {
			return new PaddedBufferedBlockCipher(bc, paddingCipher);
		}

	}

	/**
	 * @param mode
	 *            SymmetricBlockModes enum, mode name
	 * @param padding
	 *            SymmetricBlockPadding enum, padding name
	 * @return boolean true if it uses CTS
	 */
	private boolean usesCTS(SymmetricBlockMode mode, SymmetricBlockPadding padding) {
		return mode == SymmetricBlockMode.CTS || padding == SymmetricBlockPadding.WITHCTS;
	}

	/**
	 * @param algorithm
	 *            SymmetricBlockAlgorithm enum, algorithm name
	 * @return BlockCipher with the algorithm Engine
	 */
	public BlockCipher getCipherEngine(SymmetricBlockAlgorithm algorithm) {

		BlockCipher engine = null;

		switch (algorithm) {
		case AES:
			engine = new AESEngine();
			break;
		case BLOWFISH:
			engine = new BlowfishEngine();
			break;
		case CAMELLIA:
			engine = new CamelliaEngine();
			break;
		case CAST5:
			engine = new CAST5Engine();
			break;
		case CAST6:
			engine = new CAST6Engine();
			break;
		case DES:
			engine = new DESEngine();
			break;
		case TRIPLEDES:
			engine = new DESedeEngine();
			break;
		case DSTU7624_128:
			engine = new DSTU7624Engine(
					SymmetricBlockAlgorithm.getBlockSize(SymmetricBlockAlgorithm.DSTU7624_128, this.error));
			break;
		case DSTU7624_256:
			engine = new DSTU7624Engine(
					SymmetricBlockAlgorithm.getBlockSize(SymmetricBlockAlgorithm.DSTU7624_256, this.error));
			break;
		case DSTU7624_512:
			engine = new DSTU7624Engine(
					SymmetricBlockAlgorithm.getBlockSize(SymmetricBlockAlgorithm.DSTU7624_512, this.error));
			break;
		case GOST28147:
			engine = new GOST28147Engine();
			break;
		case NOEKEON:
			engine = new NoekeonEngine();
			break;
		case RC2:
			engine = new RC2Engine();
			break;
		case RC532:
			engine = new RC532Engine();
			break;
		case RC564:
			engine = new RC564Engine();
			break;
		case RC6:
			engine = new RC6Engine();
			break;
		case RIJNDAEL_128:
			engine = new RijndaelEngine(
					SymmetricBlockAlgorithm.getBlockSize(SymmetricBlockAlgorithm.RIJNDAEL_128, this.error));
			break;
		case RIJNDAEL_160:
			engine = new RijndaelEngine(
					SymmetricBlockAlgorithm.getBlockSize(SymmetricBlockAlgorithm.RIJNDAEL_160, this.error));
			break;
		case RIJNDAEL_192:
			engine = new RijndaelEngine(
					SymmetricBlockAlgorithm.getBlockSize(SymmetricBlockAlgorithm.RIJNDAEL_192, this.error));
			break;
		case RIJNDAEL_224:
			engine = new RijndaelEngine(
					SymmetricBlockAlgorithm.getBlockSize(SymmetricBlockAlgorithm.RIJNDAEL_224, this.error));
			break;
		case RIJNDAEL_256:
			engine = new RijndaelEngine(
					SymmetricBlockAlgorithm.getBlockSize(SymmetricBlockAlgorithm.RIJNDAEL_256, this.error));
			break;
		case SEED:
			engine = new SEEDEngine();
			break;
		case SERPENT:
			engine = new SerpentEngine();
			break;
		case SKIPJACK:
			engine = new SkipjackEngine();
			break;
		case SM4:
			engine = new SM4Engine();
			break;
		case TEA:
			engine = new TEAEngine();
			break;
		case THREEFISH_256:
			engine = new ThreefishEngine(
					SymmetricBlockAlgorithm.getBlockSize(SymmetricBlockAlgorithm.THREEFISH_256, this.error));
			break;
		case THREEFISH_512:
			engine = new ThreefishEngine(
					SymmetricBlockAlgorithm.getBlockSize(SymmetricBlockAlgorithm.THREEFISH_512, this.error));
			break;
		case THREEFISH_1024:
			engine = new ThreefishEngine(
					SymmetricBlockAlgorithm.getBlockSize(SymmetricBlockAlgorithm.THREEFISH_1024, this.error));
			break;
		case TWOFISH:
			engine = new TwofishEngine();
			break;
		case XTEA:
			engine = new XTEAEngine();
			break;
		default:
			this.error.setError("SB020", "Cipher " + algorithm + " not recognised.");
			break;
		}
		return engine;

	}

	/**
	 * @param padding
	 *            SymmetricBlockPadding enum, padding name
	 * @return BlockCipherPadding with loaded padding type, if padding is WITHCTS
	 *         returns null
	 */
	private BlockCipherPadding getPadding(SymmetricBlockPadding padding) {

		BlockCipherPadding paddingCipher = null;

		switch (padding) {
		case NOPADDING:
			paddingCipher = null;
			break;
		case ISO10126D2PADDING:
			paddingCipher = new ISO10126d2Padding();
			break;
		case PKCS7PADDING:
			paddingCipher = new PKCS7Padding();
			break;
		case WITHCTS:
			break;
		case X923PADDING:
			paddingCipher = new X923Padding();
		case ISO7816D4PADDING:
			paddingCipher = new ISO7816d4Padding();
			break;
		case ZEROBYTEPADDING:
			paddingCipher = new ZeroBytePadding();
			break;
		default:
			this.error.setError("SB018", "Cipher " + padding + " not recognised.");
			break;
		}
		return paddingCipher;
	}

	/**
	 * @param blockCipher
	 *            BlockCipher engine
	 * @param mode
	 *            SymmetricBlockModes enum, symmetric block mode name
	 * @return AEADBlockCipher loaded with a given BlockCipher
	 */
	private AEADBlockCipher getAEADCipherMode(BlockCipher blockCipher, SymmetricBlockMode mode) {

		AEADBlockCipher bc = null;

		switch (mode) {
		case AEAD_CCM:
			bc = new CCMBlockCipher(blockCipher);
			break;
		case AEAD_EAX:
			bc = new EAXBlockCipher(blockCipher);
			break;
		case AEAD_GCM:
			bc = new GCMBlockCipher(blockCipher);
			break;
		case AEAD_KCCM:
			bc = new KCCMBlockCipher(blockCipher);
			break;
		default:
			this.error.setError("SB017", "AEADCipher " + mode + " not recognised.");
			break;
		}
		return bc;

	}

	/**
	 * @param blockCipher
	 *            BlockCipher loaded with the algorithm Engine
	 * @param mode
	 *            SymmetricBlockModes enum, mode name
	 * @return BlockCipher with mode loaded
	 */
	private BlockCipher getCipherMode(BlockCipher blockCipher, SymmetricBlockMode mode) {

		BlockCipher bc = null;

		switch (mode) {
		case ECB:
		case NONE:
			bc = blockCipher;
			break;
		case CBC:
			bc = new CBCBlockCipher(blockCipher);
			break;
		case CFB:
			bc = new CFBBlockCipher(blockCipher, blockCipher.getBlockSize());
			break;
		case CTR:
			bc = new SICBlockCipher(blockCipher);
			break;
		case CTS:
			bc = new CBCBlockCipher(blockCipher);
			break;
		case GOFB:
			bc = new GOFBBlockCipher(blockCipher);
			break;
		case OFB:
			bc = new OFBBlockCipher(blockCipher, blockCipher.getBlockSize());
			break;
		case OPENPGPCFB:
			bc = new OpenPGPCFBBlockCipher(blockCipher);
			break;
		case SIC:
			if (blockCipher.getBlockSize() < 16) {
				this.error.setError("SB016",
						"Warning: SIC-Mode can become a twotime-pad if the blocksize of the cipher is too small. Use a cipher with a block size of at least 128 bits (e.g. AES)");
			}
			blockCipher = new SICBlockCipher(blockCipher);
			break;

		default:
			this.error.setError("SB021", "Ciphermode  " + mode + " not recognised.");
			break;

		}
		return bc;
	}
	
}
