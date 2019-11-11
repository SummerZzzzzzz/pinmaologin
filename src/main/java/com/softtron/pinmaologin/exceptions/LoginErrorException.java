package com.softtron.pinmaologin.exceptions;

public class LoginErrorException extends CommonException {
	
	public LoginErrorException(String detail,String code) {
		super(detail,code);
	}
}
