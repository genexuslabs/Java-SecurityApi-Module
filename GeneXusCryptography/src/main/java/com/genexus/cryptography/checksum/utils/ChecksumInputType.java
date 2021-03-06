package com.genexus.cryptography.checksum.utils;

import java.io.File;
import java.nio.file.Files;

import com.genexus.securityapicommons.commons.Error;
import com.genexus.securityapicommons.config.EncodingUtil;
import com.genexus.securityapicommons.utils.SecurityUtils;

public enum ChecksumInputType {

	BASE64, HEX, TXT, ASCII, LOCAL_FILE;

	public static ChecksumInputType getChecksumInputType(String checksumInputType, Error error) {
		switch (checksumInputType.toUpperCase().trim()) {
		case "BASE64":
			return ChecksumInputType.BASE64;
		case "HEX":
			return ChecksumInputType.HEX;
		case "TXT":
			return ChecksumInputType.TXT;
		case "ASCII":
			return ChecksumInputType.ASCII;
		case "LOCAL_FILE":
			return ChecksumInputType.LOCAL_FILE;
		default:
			error.setError("CI001", "Unrecognized checksum input type");
			return null;
		}
	}

	public static String valueOf(ChecksumInputType checksumInputType, Error error) {
		switch (checksumInputType) {
		case BASE64:
			return "BASE64";
		case HEX:
			return "HEX";
		case TXT:
			return "TXT";
		case ASCII:
			return "ASCII";
		case LOCAL_FILE:
			return "LOCAL_FILE";
		default:
			error.setError("CI002", "Unrecognized checksum input type");
			return "";
		}
	}

	public static byte[] getBytes(ChecksumInputType checksumInputType, String input, Error error) {
		EncodingUtil eu = new EncodingUtil();
		byte[] aux = null;
		switch (checksumInputType) {
		case BASE64:
			try {
				aux = org.bouncycastle.util.encoders.Base64.decode(input);
			} catch (Exception e) {
				error.setError("CI003", e.getMessage());
			}
			break;
		case HEX:
			aux = SecurityUtils.getHexa(input, "CI004", error);
			break;
		case TXT:
			aux = eu.getBytes(input);
			if (eu.hasError()) {
				error = eu.getError();
			}
			break;
		case ASCII:
			try {
				aux = input.getBytes("US-ASCII");
			} catch (Exception e) {
				error.setError("CI004", e.getMessage());
			}
			break;
		case LOCAL_FILE:
			try {
				File initialFile = new File(input);
				aux = Files.readAllBytes(initialFile.toPath());
			} catch (Exception e) {
				error.setError("CI005", e.getMessage());
			}
			break;
		default:
			error.setError("CI006", "Unrecognized checksum input type");
			break;
		}
		return aux;
	}
}
