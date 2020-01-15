package com.genexus.JWT.claims;

import java.util.List;

import com.genexus.securityapicommons.commons.Error;

public final class PrivateClaims extends Claims {

	private List<Claim> claims;

	public PrivateClaims() {
		super();
	}

	public boolean setClaim(String key, String value) {
		return super.setClaim(key, value, new Error());
	}
}
