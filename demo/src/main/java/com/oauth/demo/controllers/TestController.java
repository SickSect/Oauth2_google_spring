package com.oauth.demo.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class TestController {

    @GetMapping
    public String home(@RequestParam(name = "logout", required = false, defaultValue = "true") boolean logout){
        return "index";
    }

    @GetMapping("/login")
    public String login(){
        return "app-user/login";
    }
}
