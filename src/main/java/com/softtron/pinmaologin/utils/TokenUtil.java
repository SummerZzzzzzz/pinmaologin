package com.softtron.pinmaologin.utils;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.softtron.pinmaologin.daos.UserDao;
import com.softtron.pinmaologin.domains.TUser;
@Component
public class TokenUtil {
	@Autowired
	UserDao userDao;
	Map<String, TUser> userMap = new HashMap<>();

	/**
	 * 保存中户跟key的关系
	 * 
	 * @param user
	 * @return
	 */
	public String saveUser(String randomKey,TUser user) {
		userMap.put(randomKey, user);
		return randomKey;
	}

	/**
	 * 根据key查找用户，如果用户在map中，则返回 如果用户在数据库中，则返回 如果用户不存在，需要注册
	 * 
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public TUser getUser(String key) throws Exception {
		TUser user = null;
		if ((user = userMap.get(key)) != null) {
			return user;
		} else if ((user = userDao.findUserByToken(key)) != null) {
			return user;
		} else {
			throw ExceptionUtil.NOTUSEREXCEPTION;
		}
	}
}
