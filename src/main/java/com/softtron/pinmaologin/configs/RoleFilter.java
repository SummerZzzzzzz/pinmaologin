package com.softtron.pinmaologin.configs;

import java.io.IOException;
import java.util.Set;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;

import com.softtron.pinmaologin.utils.ExceptionUtil;
import com.softtron.pinmaologin.utils.TokenSubjectUtil;

public class RoleFilter extends AuthorizationFilter {
	@Override
	public boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws IOException {
		HttpServletRequest httpServletRequest = (HttpServletRequest) request;
		System.out.println(httpServletRequest.getServletPath());
		String token = httpServletRequest.getParameter("token");
		Subject subject = TokenSubjectUtil.getSubject(token);
		if (subject == null) {
//			response.setContentType("application/json;charset=utf-8");
//			response.getWriter().write("{\"code\":50005,\"message\":\"未登录\"}");
			// subject = this.getSubject(request, response);
			return false;
		}
		boolean flat = false;
//			    Subject subject = this.getSubject(request, response);
//		        //获取当前路径所需要的角色
		String[] rolesArray = (String[]) mappedValue;
		// 如果有配置，那说明对角色有要求
		if (rolesArray != null && rolesArray.length != 0) {
			Set<String> roles = CollectionUtils.asSet(rolesArray);

			for (String item : roles) {
				// 判断是否有这个角色
				if (subject.hasRole(item)) {
					flat = true;
				}
			}
		}
		return flat;
	}

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {
		// throw ExceptionUtil.NOLOGIN;
		// return false;
		response.setContentType("application/json;charset=utf-8");
		response.getWriter().write("{\"code\":50003,\"message\":\"未授权!\"}");
		return false;
	}

}
