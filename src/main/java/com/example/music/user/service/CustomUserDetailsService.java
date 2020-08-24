package com.example.music.user.service;

import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
import com.example.common.users.UserEntity;
import com.example.common.utils.Md5Utils;
import com.example.music.user.mapper.UserMapper;
import org.apache.commons.lang.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component("customUserDetailsService")
public class CustomUserDetailsService {

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public UserEntity loadUserByUsername(String username) throws UsernameNotFoundException {
       return loadUserByUsername(username,"86");
    }

    public UserEntity loadUserByUserId(long id) throws UsernameNotFoundException {
        return loadUserByUserId(String.valueOf(id));
    }

    public UserEntity loadUserByUserId(String id) throws UsernameNotFoundException {
        UserEntity byPhone = userMapper.selectById(id);
        if (byPhone == null) {
            throw new UsernameNotFoundException("");
        }
        return byPhone;
    }

    public UserEntity loadUserByUsername(String phone,String area) throws UsernameNotFoundException {
        UserEntity byPhone = userMapper.findByPhone(phone,area);
        if (byPhone == null) {
            byPhone = createNew(phone,area);
        }
        return byPhone;
    }


    public UserEntity createNew(String username,String area) {
        UserEntity userEntity = new UserEntity();
        userEntity.setNickname(RandomStringUtils.randomAlphabetic(6));
        userEntity.setPhone(username);
        String password = passwordEncoder.encode(RandomStringUtils.randomAlphanumeric(16));
        userEntity.setPassword(password);
        userEntity.setArea(area);
        userEntity.setId(Long.parseLong(RandomStringUtils.randomNumeric(10)));
        if (userMapper.insert(userEntity) <= 0) {
            return null;
        }
        return userEntity;
    }

    public boolean updatePasswordById(long id,String password) {
        return updatePasswordById(String.valueOf(id),password);
    }

    /**
     * 更新用户密码
     * @param id
     * @param password
     * @return
     */
    public boolean updatePasswordById(String id,String password) {
        String newPassword = passwordEncoder.encode(Md5Utils.encode(password));
        UpdateWrapper<UserEntity> userEntityUpdateWrapper = new UpdateWrapper<UserEntity>()
                .eq("id",id)
                .set("password",newPassword);
        return userMapper.update(null,userEntityUpdateWrapper) > 0;
    }

    /**
     * 更新用户头像
     * @param id
     * @param avatar
     * @return
     */
    public int updateAvatar(String id,String avatar) {
        UpdateWrapper<UserEntity> userEntityUpdateWrapper = new UpdateWrapper<UserEntity>()
                .eq("id",id)
                .set("avatar",avatar);
        return userMapper.update(null,userEntityUpdateWrapper);
    }

}
