package com.example.music.user.controller.auth;

import com.example.common.rep.HttpResponse;
import com.example.music.user.service.RedisTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/sms")
public class SmsController {

    @Autowired
    private RedisTokenService redisTokenService;

    @PostMapping("send")
    public Object sendCode(@RequestParam(value = "type") String type,
                           @RequestParam("phone") String phone,
                           @RequestParam("area") String area) {
        return HttpResponse.success(redisTokenService.generateSmsCode(phone, area,type));
    }
}
