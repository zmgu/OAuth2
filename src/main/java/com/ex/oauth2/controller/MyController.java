package com.ex.oauth2.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
public class MyController {

    @GetMapping("/my")
    public String myPage() {

        return "my";
    }
}