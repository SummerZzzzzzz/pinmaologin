package com.softtron.pinmaologin.daos;

import java.util.Map;
import java.util.Set;

import org.apache.ibatis.annotations.Result;
import org.apache.ibatis.annotations.Results;
import org.apache.ibatis.annotations.Select;

import com.softtron.pinmaologin.domains.TUser;

public interface UserDao {
	public TUser findUserByToken(String key);
    public TUser findUserByUsername(String username);
	public TUser findUser(Map map);
    public Set<String> getRole(String username);
	public void insertUser(Map map);
}
