package com.example.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class DemoController {
    

    @RequestMapping(path = "/**")
    public ResponseEntity<String> catchAll() {

        String principal = SecurityContextHolder.getContext().getAuthentication().getName();
        String roles = SecurityContextHolder.getContext().getAuthentication().getAuthorities().toString();

        return ResponseEntity.ok(String.format("%s:%s", principal, roles));
    }
}
