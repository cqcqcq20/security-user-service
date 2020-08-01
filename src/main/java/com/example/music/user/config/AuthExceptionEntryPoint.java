package com.example.music.user.config;

import com.example.common.rep.HttpResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * Created on 2018/5/24 0024.
 *
 * @author zlf
 * @email i@merryyou.cn
 * @since 1.0
 */
public class AuthExceptionEntryPoint implements AuthenticationEntryPoint {


    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws ServletException {
        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.writeValue(response.getOutputStream(), HttpResponse.failure(HttpServletResponse.SC_UNAUTHORIZED,authException.getMessage()));
        } catch (Exception e) {
            throw new ServletException();
        }
    }
}