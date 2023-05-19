package com.sky.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.Mapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @ClassName LoginController
 * @Description TODO
 * @Author sky
 * @Date 2023/5/17 11:47
 * @Version 1.0
 **/
@Controller
public class LoginController {

    @RequestMapping("/login/oauth2")
    public String gotoLoginPage() {
        return "login.html";
    }
}
