package com.genexus.JWT.utils;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import com.genexus.commons.DateUtilObject;

public final class DateUtil extends DateUtilObject{

	/******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/
	public String getCurrentDate() {
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
		LocalDateTime now = LocalDateTime.now();
		return dtf.format(now);
	}
	
	public String currentPlusSeconds(long seconds) {
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
		LocalDateTime now = LocalDateTime.now();
		now.plusSeconds(seconds);
		return dtf.format(now);
	}
	
	public String currentMinusSeconds(long seconds) {
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
		LocalDateTime now = LocalDateTime.now();
		now.minusSeconds(seconds);
		return dtf.format(now);
	}
	/******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

}
