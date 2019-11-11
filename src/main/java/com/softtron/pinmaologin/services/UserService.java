package com.softtron.pinmaologin.services;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.softtron.pinmaologin.daos.UserDao;
import com.softtron.pinmaologin.domains.TUser;
import com.softtron.pinmaologin.utils.ExceptionUtil;
import com.softtron.pinmaologin.utils.TokenUtil;

@Service
public class UserService {
	@Autowired
	TokenUtil tokenUtil;
	@Autowired
	private UserDao userDao;

	public String login(Map map) throws Exception {
		TUser user =null;
		user = userDao.findUserByUsername((String)map.get("username"));
		if (user == null) {//未注册
			throw ExceptionUtil.NOTUSEREXCEPTION;
		}
		user = userDao.findUser(map);
		if (user == null) {//用户名密码错误
			throw ExceptionUtil.LOGINERROREXCEPTION;
		}else {
			tokenUtil.saveUser(user.getToken(), user);
		}
		return user.getToken();
	}
	 public Set<String> getRole(String username){
		 return userDao.getRole(username);
	 }
	 
	 public TUser getUser(String username) {
		 return userDao.findUserByUsername(username);
	 }
}
