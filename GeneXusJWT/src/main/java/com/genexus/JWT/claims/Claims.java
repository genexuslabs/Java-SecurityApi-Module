package com.genexus.JWT.claims;

import java.util.ArrayList;
import java.util.List;

import com.genexus.JWT.utils.JWTUtils;
import com.genexus.securityapicommons.commons.Error;
import com.genexus.securityapicommons.utils.SecurityUtils;

public class Claims {

	private List<Claim> claims;

	public Claims() {
		claims = new ArrayList<Claim>();
	}

	public boolean setClaim(String key, String value, Error error) {
		Claim claim = new Claim(key, value);
		claims.add(claim);
		return true;
	}

	public List<Claim> getAllClaims() {
		return claims;
	}

	public String getClaimValue(String key, Error error) {
		for (int i = 0; i < claims.size(); i++) {
			if (SecurityUtils.compareStrings(key, claims.get(i).getKey())) {
				return claims.get(i).getValue();
			}
		}
		error.setError("CL001", "Could not find a claim with" + key + " key value");
		return "";
	}

	public boolean isEmpty() {
		if (claims.size() == 0) {
			return true;
		} else {
			return false;

		}
	}
}
