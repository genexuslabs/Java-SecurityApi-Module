package com.genexus.JWT.claims;

public class Claim {

	private String key;
	private String value;

	public Claim(String valueKey, String valueOfValue) {
		key = valueKey;
		value = valueOfValue;
	}

	public String getValue() {
		return value;
	}

	public String getKey() {
		return key;
	}
}
