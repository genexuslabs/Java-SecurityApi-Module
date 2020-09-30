package com.genexus.securityapicommons.utils;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import com.genexus.securityapicommons.commons.Error;

import org.bouncycastle.util.encoders.Hex;

import com.genexus.securityapicommons.commons.SecurityAPIObject;
import com.genexus.securityapicommons.config.EncodingUtil;

public class SecurityUtils {

	public static boolean compareStrings(String one, String two) {
		if (one != null && two != null) {
			return one.compareToIgnoreCase(two) == 0;
		} else {
			return false;
		}

	}

	public static boolean validateExtension(String path, String extension) {
		if (extensionIs(path, extension)) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * @param path
	 *            path to the file
	 * @return file extension
	 */
	public static String getFileExtension(String path) {

		int lastIndexOf = path.lastIndexOf(".");
		if (lastIndexOf == -1) {
			return ""; // empty extension
		}
		return path.substring(lastIndexOf);
	}

	/**
	 * @param path
	 *            path to the file
	 * @param ext
	 *            extension of the file
	 * @return true if the file has the extension
	 */
	public static boolean extensionIs(String path, String ext) {
		return getFileExtension(path).compareToIgnoreCase(ext) == 0;
	}

	public static KeyFactory getKeyFactory(String algorithm) throws NoSuchAlgorithmException {
		KeyFactory kf = null;
		if (compareStrings("ECDSA", algorithm)) {
			kf = kf.getInstance("EC");
		} else {
			kf = kf.getInstance("RSA");
		}
		return kf;

	}

	private static final InputStream inputStringtoStream(String text) {
		return new ByteArrayInputStream(new EncodingUtil().getBytes(text));
	}

	public static final InputStream inputFileToStream(String path) throws IOException {
		final File initialFile = new File(path);
		final InputStream targetStream = new DataInputStream(new FileInputStream(initialFile));
		return targetStream;
	}
	
	public static byte[] getHexa(String hex, String code, Error error)
	{
		byte[] output;
		try 
		{
			output = Hex.decode(hex);
		}catch(Exception e)
		{
			error.setError(code, e.getMessage());
			return null;
		}
		return output;
	}
}
