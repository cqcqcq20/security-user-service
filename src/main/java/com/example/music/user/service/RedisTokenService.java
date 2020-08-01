package com.example.music.user.service;

import com.alibaba.fastjson.JSON;
import com.example.common.sms.SmsEntity;
import org.apache.commons.lang.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;

import java.util.Map;
import java.util.concurrent.TimeUnit;

@Component
public class RedisTokenService {

    @Value("${sms.verify.length}")
    private int codeLength;

    @Value("${sms.verify.expMin}")
    private int expMin;

    public static final int MIL = 1000 * 60;

    @Autowired
    StringRedisTemplate redisTemplate;

    public SmsEntity generateSmsCode(String phone, String area, String type) {
        return generateSmsCode(phone,area,type,expMin);
    }

    public SmsEntity generateSmsCode(String phone, String area,String type,int expMin) {
        String code = RandomStringUtils.randomNumeric(codeLength);
        ValueOperations<String, String> stringStringValueOperations = redisTemplate.opsForValue();
        stringStringValueOperations.set(String.format("%s:%s:%s",phone,area,type),code,expMin, TimeUnit.MINUTES);
        SmsEntity smsEntity = new SmsEntity();
        smsEntity.setCode(code);
        smsEntity.setSendTs(System.currentTimeMillis());
        smsEntity.setExpireTs(System.currentTimeMillis() + (MIL * expMin));
        return smsEntity;
    }

    public String getVerificationCode(String phone,String area,String type) {
        String keyName = String.format("%s:%s:%s",phone,area,type);
        ValueOperations<String, String> stringStringValueOperations = redisTemplate.opsForValue();
        return stringStringValueOperations.get(keyName);
    }

    public void removeVerificationCode(String phone,String area,String type) {
        String keyName = String.format("%s:%s:%s",phone,area,type);
        redisTemplate.delete(keyName);
    }


}
