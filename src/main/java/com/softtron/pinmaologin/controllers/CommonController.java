package com.softtron.pinmaologin.controllers;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

public class CommonController {
	public Map resultMap() {
		Map map = new HashMap<>();
		map.put("code", "200");
		map.put("message", "操作成功!");
		return map;
	}
	
	
}
