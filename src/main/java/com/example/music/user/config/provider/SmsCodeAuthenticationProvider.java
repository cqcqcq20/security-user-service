package com.example.music.user.config.provider;

import com.example.common.exception.BadRequestException;
import com.example.common.users.UserEntity;
import com.example.music.user.config.token.SmsCodeAuthenticationToken;
import com.example.music.user.service.CustomUserDetailsService;
import com.example.music.user.service.RedisTokenService;
import lombok.Data;
import org.apache.commons.lang.StringUtils;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.ArrayList;

@Data
public class SmsCodeAuthenticationProvider implements AuthenticationProvider {

    private RedisTokenService redisTokenService;

    private CustomUserDetailsService customUserDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        //这个authentication就是SmsCodeAuthenticationToken
        SmsCodeAuthenticationToken authenticationToken = (SmsCodeAuthenticationToken) authentication;

        String phone = (String) authenticationToken.getPrincipal();
        String area = authenticationToken.getArea();
        String type = authenticationToken.getType();
        // 验证验证码
        String smsCodeCached = redisTokenService.getVerificationCode(phone,area,type);

        String smscode = authenticationToken.getCode();
        if (StringUtils.isEmpty(smsCodeCached) || !smscode.equals(smsCodeCached)) {
            throw new BadRequestException("验证码错误");
        } else {
            redisTokenService.removeVerificationCode(phone,area,type);
        }

        //校验手机号
        UserEntity user = customUserDetailsService.loadUserByUsername(phone,area);
        //这时候已经认证成功了
        SmsCodeAuthenticationToken authenticationResult = new SmsCodeAuthenticationToken(user,area,type, new ArrayList<>());
        authenticationResult.setDetails(authenticationToken.getDetails());

        return authenticationResult;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SmsCodeAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
