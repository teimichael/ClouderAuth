package stu.napls.clouderauth;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class Encoder {
    @Test
    public void bCryptPasswordEncoding() {
        String password = "NabootAuth#!$";
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String encode = bCryptPasswordEncoder.encode(password);
        System.out.println(encode);
        assert bCryptPasswordEncoder.matches(password, encode);
    }
}