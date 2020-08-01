package com.example.music.user.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.common.users.UserEntity;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Component;

@Component("userMapper")
public interface UserMapper extends BaseMapper<UserEntity> {

    @Select("select * from user where phone = #{phone} and area = #{area} limit 1")
    UserEntity findByPhone(String phone,String area);

}
