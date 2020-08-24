package com.example.music.user.controller.auth;

import com.example.common.exception.BasicErrorCode;
import com.example.common.rep.HttpResponse;
import com.example.common.users.UserEntity;
import com.example.common.utils.Md5Utils;
import com.example.log.ApiLog;
import com.example.music.user.config.token.CustomRemoteTokenServices;
import com.example.music.user.config.token.SmsCodeAuthenticationToken;
import com.example.music.user.service.CustomUserDetailsService;
import org.example.vlidator.annotation.CheckParam;
import org.example.vlidator.annotation.CheckParams;
import org.example.vlidator.utils.Validat;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController()
@RequestMapping("/password")
public class PasswordController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private CustomRemoteTokenServices customRemoteTokenServices;

    @Value("${app.password.matches}")
    private String matches;

    @PostMapping("reset")
    @PreAuthorize("hasAnyAuthority('app')")
    @ApiLog(module = "user",desc = "修改密码")
    @CheckParams({
            @CheckParam(value = Validat.Password, argName = "oldPassword"),
            @CheckParam(value = Validat.Password, argName = "password"),
            @CheckParam(value = Validat.NotNull, argName = "refreshToken"),
    })
    public Object reset(Principal principal, String oldPassword, String password,String refreshToken) {

        UserEntity userDetails = customUserDetailsService.loadUserByUserId(principal.getName());
        if (!passwordEncoder.matches(Md5Utils.encode(oldPassword),userDetails.getPassword())) {
            return HttpResponse.failure(BasicErrorCode.PASSWORD_NOT_MATCH);
        }
        if (customUserDetailsService.updatePasswordById(principal.getName(),password)) {
            return HttpResponse.failure(BasicErrorCode.PASSWORD_UPDATE_FAILURE);
        }

        customRemoteTokenServices.refreshToken(refreshToken);

        return HttpResponse.success();
    }

    @PostMapping("forget")
    @ApiLog(module = "auth",desc = "忘记密码")
    @CheckParams({
            @CheckParam(value = Validat.NotNull, argName = "phone" , msg = "手机号不能为空"),
            @CheckParam(value = Validat.NotNull, argName = "area" , msg = "区号不能为空"),
            @CheckParam(value = Validat.NotNull, argName = "code" , msg = "验证码不能为空"),
            @CheckParam(value = Validat.Password, argName = "password" , msg = "密码不合法"),
    })
    public HttpResponse<?> forget(String phone, String area, String code, String password) {
        Authentication authentication = authenticationManager.authenticate(new SmsCodeAuthenticationToken(
                phone, code, area, "forget"
        ));
        User userPrincipal = (User) authentication.getPrincipal();
        if (!customUserDetailsService.updatePasswordById(userPrincipal.getUsername(), password)) {
            return HttpResponse.failure(BasicErrorCode.VALIDATOR_FAILURE_ERROR);
        }

        return HttpResponse.success();
    }
}
