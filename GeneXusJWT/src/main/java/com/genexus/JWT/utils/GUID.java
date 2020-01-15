package com.genexus.JWT.utils;

import java.util.UUID;

import com.genexus.commons.GUIDObject;

public final class GUID extends GUIDObject{

	/******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/
	public String generate() {
		UUID uuid = UUID.randomUUID();

		return uuid.toString();// .replaceAll("-", "").toUpperCase();
	}
	/******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/
}
