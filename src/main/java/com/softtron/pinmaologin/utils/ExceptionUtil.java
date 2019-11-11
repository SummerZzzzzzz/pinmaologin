package com.softtron.pinmaologin.utils;

import org.apache.shiro.authc.AuthenticationException;

import com.softtron.pinmaologin.exceptions.LoginErrorException;
import com.softtron.pinmaologin.exceptions.NoLoginException;
import com.softtron.pinmaologin.exceptions.NotPremissionException;
import com.softtron.pinmaologin.exceptions.NotTokenException;
import com.softtron.pinmaologin.exceptions.NotUserException;

public class ExceptionUtil {
    public static final AuthenticationException NOTUSEREXCEPTION = new NotUserException("用户未注册", "50001");
    public static final AuthenticationException LOGINERROREXCEPTION = new LoginErrorException("用户名或密码错误", "50002");
    public static final NotPremissionException NOTPREMISSIONEXCEPTION = new NotPremissionException("无权限","50003");
    public static final NotTokenException NOTTOKEN = new NotTokenException("token无效","50004");
    public static final NoLoginException NOLOGIN = new NoLoginException("未登录","50005");
}
