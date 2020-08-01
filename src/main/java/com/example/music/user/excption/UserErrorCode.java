package com.example.music.user.excption;

import com.example.common.exception.ErrorCode;

public enum UserErrorCode implements ErrorCode {

    VERIFY_CODE_INVIABLE(10020,"验证码错误");

    private int code;

    private String msg;

    UserErrorCode(int code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }
}
