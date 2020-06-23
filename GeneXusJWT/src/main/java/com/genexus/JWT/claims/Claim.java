package com.genexus.JWT.claims;

public class Claim {

	private String key;
	private Object value;

	public Claim(String valueKey, Object valueOfValue) {
		key = valueKey;
		value = valueOfValue;
	} 

	public String getValue() {
		if (value instanceof String) {
			return (String) value;
		} else {
			return null;
		}
	}

	public PrivateClaims getNestedClaims() {
		if (value instanceof PrivateClaims) {
			return (PrivateClaims) value;
		} else {
			return null;
		}
	}

	public String getKey() {
		return key;
	}
}
