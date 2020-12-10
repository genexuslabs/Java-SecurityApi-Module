package com.genexus.JWT.claims;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.genexus.securityapicommons.commons.Error;

public final class PrivateClaims extends Claims {

	private List<Claim> claims;


	public PrivateClaims() {
		super();
	
	}
 
	public boolean setClaim(String key, Object value) {
		return super.setClaim(key, value, new Error());
	}
	
	public boolean setClaim(String key, PrivateClaims value)
	{
		
		return super.setClaim(key, value, new Error());
	}

	public Map<String, Object> getNestedMap() {
		HashMap<String, Object> result = new HashMap<String, Object>();
		for (Claim c : getAllClaims()) {
			if (c.getValue() != null) {
				result.put(c.getKey(), c.getValue());
			} else {
				result.put(c.getKey(), ((PrivateClaims) c.getNestedClaims()).getNestedMap());
			}
		}

		return result;
	}

}
