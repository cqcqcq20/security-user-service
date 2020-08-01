package com.example.music.user;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.example.common.users.UserEntity;
import com.example.music.user.mapper.UserMapper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.List;

@RunWith(SpringRunner.class)
@SpringBootTest
public class UserTest {

    @Autowired
    private UserMapper userMapper;

    @Test
    public void testUserList() {
        List<UserEntity> userEntities = userMapper.selectList(null);
        userEntities.forEach(System.out::println);
    }

    @Test
    public void testFindByPhone() {
        UserEntity userEntities = userMapper.findByPhone("123456","86");
        System.out.println(userEntities);
    }

    @Test
    public void testQueryWrapper() {
        QueryWrapper<UserEntity> queryWrapper = new QueryWrapper<UserEntity>().gt("id", 0).select("id","password","phone");
        List<UserEntity> userEntities = userMapper.selectList(queryWrapper);
        userEntities.forEach(System.out::println);
    }
}
