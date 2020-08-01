package com.example.music.user.service;

import com.alibaba.fastjson.JSON;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.TimeUnit;

@Component
public class LocalAccessTokenService {

    @Value("${security.oauth2.client.exp-sec}")
    private int exp;

    @Autowired
    StringRedisTemplate redisTemplate;

    public void storeAccessToken(String access, Map<String, Object> map, long expireAt) {
        ValueOperations<String, String> stringStringValueOperations = redisTemplate.opsForValue();
        long live = Math.max(5,expireAt - System.currentTimeMillis() / 1000);
        live = Math.min(live, exp);
        stringStringValueOperations.set(access, JSON.toJSONString(map),live, TimeUnit.SECONDS);
    }

    public void removeToken(String access) {
        redisTemplate.delete(access);
    }

    public Map<String, Object> getAccessToken(String access) {
        ValueOperations<String, String> stringStringValueOperations = redisTemplate.opsForValue();
        String token = stringStringValueOperations.get(access);
        return JSON.parseObject(token, Map.class);
    }
}
