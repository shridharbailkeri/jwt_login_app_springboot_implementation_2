package com.unknowncoder.controller;


import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
@CrossOrigin("*")
// annotation is used in Spring Framework-based applications to enable Cross-Origin Resource Sharing (CORS) for a specific controller or endpoint.
// CORS is a security feature implemented by web browsers that restricts web pages from making requests to a different domain than the one that served the web page.
// This security feature is designed to prevent cross-site request forgery (CSRF) and other types of attacks.
public class UserController {

    //https://github.com/unknownkoder/spring-security-login-system/tree/main/AuthenticatedBackend

    @GetMapping("/")
    public String helloUserController(){
        return "User access level";
    }
}
