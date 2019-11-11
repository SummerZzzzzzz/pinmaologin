package com.softtron.pinmaologin.configs;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;

import com.softtron.pinmaologin.utils.ExceptionUtil;
import com.softtron.pinmaologin.utils.TokenSubjectUtil;

public class NoSessionFilter extends BasicHttpAuthenticationFilter {
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
	System.out.println("isAccessAllowed");
		HttpServletRequest httpServletRequest = (HttpServletRequest) request;		System.out.println(httpServletRequest.getServletPath());
		String token = httpServletRequest.getParameter("token");
		Subject subject = TokenSubjectUtil.getSubject(token);
		if(subject == null) {
			return false;
		}
		return true;
	}

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		//throw ExceptionUtil.NOLOGIN;
		//return false;
		response.setContentType("application/json;charset=utf-8");
		response.getWriter().write("{\"code\":50005,\"message\":\"未登录\"}");
		return false;
	}
}

