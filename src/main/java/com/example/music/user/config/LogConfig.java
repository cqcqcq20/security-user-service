package com.example.music.user.config;

import com.example.log.interceptor.UidInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;

@Configuration
public class LogConfig {

    @Bean
    public UidInterceptor provideUidInterceptor() {
        return () -> {
            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            if (principal instanceof User) {
                return  ((User) principal).getUsername();
            } else if (principal instanceof String) {
                return principal.toString();
            }
            return null;
        };
    }
}
