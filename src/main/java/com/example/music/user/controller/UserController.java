package com.example.music.user.controller;

import com.example.common.exception.BasicErrorCode;
import com.example.common.rep.HttpResponse;
import com.example.common.users.UserEntity;
import com.example.log.ApiLog;
import com.example.music.auth.basic.config.token.UserInfoAuthenticationToken;
import com.example.music.user.service.CustomUserDetailsService;
import org.example.vlidator.annotation.CheckParam;
import org.example.vlidator.annotation.CheckParams;
import org.example.vlidator.utils.Validat;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.security.Principal;

@RestController
public class UserController {

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @GetMapping("/profile")
    @PreAuthorize("hasAuthority('app')")
    @ApiLog(module = "user",desc = "获取用户信息")
    public HttpResponse<?> profile(OAuth2Authentication principal) {
        return HttpResponse.success(principal.getUserAuthentication().getDetails());
    }

    @PostMapping("avatar")
    @PreAuthorize("hasAuthority('app')")
    @ApiLog(module = "user",desc = "更新用户头像")
    @CheckParams({
            @CheckParam(value = Validat.FileContentType,argName = "avatar",alias = "头像",express = "image/jpeg,image/png",msg = "请上传png、jpeg图片",code = BasicErrorCode.VALIDATOR_FAILURE_ERROR),
    })
    public HttpResponse<?> updateAvatar(Principal principal,  MultipartFile avatar) {
        String path = avatar.getOriginalFilename();
        customUserDetailsService.updateAvatar(principal.getName(),path);
        UserEntity userEntity = customUserDetailsService.loadUserByUserId(principal.getName());
        userEntity.setAvatar(path);
        return HttpResponse.success(userEntity);
    }
}
