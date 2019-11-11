package com.softtron.pinmaologin.exceptions;

import org.apache.shiro.authc.AuthenticationException;

public class CommonException extends AuthenticationException {
	protected String code;
	protected String detail;

	public CommonException(String detail, String code) {
		super(detail);
		this.detail = detail;
		this.code = code;
		
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getDetail() {
		return detail;
	}

	public void setDetail(String detail) {
		this.detail = detail;
	}

}
