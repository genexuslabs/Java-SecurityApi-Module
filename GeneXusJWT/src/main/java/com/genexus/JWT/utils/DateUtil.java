package com.genexus.JWT.utils;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoField;
import java.util.Calendar;

import com.genexus.commons.DateUtilObject;

public final class DateUtil extends DateUtilObject {

	/******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/
	public String getCurrentDate() {
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
		LocalDateTime now = LocalDateTime.now();
		return dtf.format(now);
	}

	public String currentPlusSeconds(long seconds) {
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
		LocalDateTime now = LocalDateTime.now();
		LocalDateTime aux = now.plusSeconds(seconds);
		return dtf.format(aux);
	}

	public String currentMinusSeconds(long seconds) {
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
		LocalDateTime now = LocalDateTime.now();
		LocalDateTime aux = now.minusSeconds(seconds);
		return dtf.format(aux);
	}

	public String currentPlusMinutes(long minutes) {
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
		LocalDateTime now = LocalDateTime.now();
		LocalDateTime aux = now.plusMinutes(minutes);
		return dtf.format(aux);
	}
	
	public String currentPlusHours(long hours) {
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
		LocalDateTime now = LocalDateTime.now();
		LocalDateTime aux = now.plusHours(hours);
		return dtf.format(aux);
	}

	public String currentPlusDays(long days) {
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
		LocalDateTime now = LocalDateTime.now();
		LocalDateTime aux = now.plusDays(days);
		return dtf.format(aux);
	}

	public String currentPlusMonths(int months) {
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
		LocalDateTime now = LocalDateTime.now();
		LocalDateTime aux = now.plusMonths(months);
		return dtf.format(aux);
	}

	public String lastDayOfCurrentMonth(String time) {
		LocalTime localTime;
		try {
			localTime = LocalTime.parse(time, DateTimeFormatter.ofPattern("HH:mm:ss"));
		} catch (DateTimeParseException e) {
			this.error.setError("DU001", "Wrong format in input parameter");
			return "";
		}

		int hour = localTime.get(ChronoField.CLOCK_HOUR_OF_DAY);
		int minute = localTime.get(ChronoField.MINUTE_OF_HOUR);
		int second = localTime.get(ChronoField.SECOND_OF_MINUTE);
		Calendar calendar = Calendar.getInstance();
		int day = calendar.getActualMaximum(Calendar.DATE);
		LocalDateTime now = LocalDateTime.now();
		int year = now.getYear();
		int month = now.getMonthValue();
		String result;
		try {
			result = String.format("%d/%02d/%02d %02d:%02d:%02d", year, month, day, hour, minute, second);
		} catch (java.util.IllegalFormatException e) {
			this.error.setError("DU002", "Could not generate correct date");
			return "";
		}
		return result;

	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

}
