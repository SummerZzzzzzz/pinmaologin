package com.softtron.pinmaologin.utils;

import java.util.HashMap;
import java.util.Map;

import org.apache.shiro.subject.Subject;

public class TokenSubjectUtil {
	private static  Map<String, Subject> subjectMap = new HashMap<>();
	public static void saveSubject(String randomKey,Subject sub) {
		subjectMap.put(randomKey, sub);
	}
	public static Subject getSubject(String key) {
		return subjectMap.get(key);
	}
}
