package com.genexus.securityapicommons.utils;

import java.util.ArrayList;
import java.util.List;

public class ExtensionsWhiteList {

	private List<String> whitelist;

	public ExtensionsWhiteList() {
		this.whitelist = new ArrayList<String>();
	}

	public void setExtension(String value) {
		if (value.charAt(0) != '.') {
			value = "." + value;
		}
		this.whitelist.add(value);
	}

	public boolean isValid(String path) {
		if (!isValidName(path)) {
			return false;
		}
		String ext = SecurityUtils.getFileExtension(path);
		for (int i = 0; i < this.whitelist.size(); i++) {
			if (SecurityUtils.compareStrings(ext, this.whitelist.get(i))) {
				return true;
			}
		}
		return false;
	}

	public boolean isEmpty() {
		if (this.whitelist.size() == 0) {
			return true;
		}
		return false;
	}

	private boolean isValidName(String path) {
		int counter = 0;
		int i = 0;
		while (i < path.length() && counter <= 2) {
			if (path.charAt(i) == '.') {
				counter++;
			}
			i++;
		}
		if (counter >= 2) {
			return false;
		}
		return true;
	}
}
