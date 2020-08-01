package com.example.music.user.config;

import com.example.music.auth.basic.config.UnAuthenticationEntryPoint;
import com.example.music.auth.basic.config.handler.AuthAccessDeniedHandler;
import com.example.music.user.config.provider.SmsCodeAuthenticationProvider;
import com.example.music.user.service.CustomUserDetailsService;
import com.example.music.user.service.RedisTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private RedisTokenService redisTokenService;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authenticationProvider(authenticationProvider())
                .exceptionHandling().accessDeniedHandler(new AuthAccessDeniedHandler()).authenticationEntryPoint(provideUnAuthenticationEntryPoint());
    }

    private UnAuthenticationEntryPoint provideUnAuthenticationEntryPoint() {
        return new UnAuthenticationEntryPoint();
    }

    private SmsCodeAuthenticationProvider authenticationProvider() {
        SmsCodeAuthenticationProvider smsCodeAuthenticationProvider = new SmsCodeAuthenticationProvider();
        smsCodeAuthenticationProvider.setRedisTokenService(redisTokenService);
        smsCodeAuthenticationProvider.setCustomUserDetailsService(customUserDetailsService);
        return smsCodeAuthenticationProvider;
    }
}
