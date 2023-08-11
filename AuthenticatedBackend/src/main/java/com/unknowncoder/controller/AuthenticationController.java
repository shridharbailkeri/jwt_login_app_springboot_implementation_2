package com.unknowncoder.controller;

import com.unknowncoder.models.ApplicationUser;
import com.unknowncoder.models.LoginResponseDTO;
import com.unknowncoder.models.RegistrationDto;
import com.unknowncoder.services.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@CrossOrigin("*") // just so that we r not getting blocked by any cors issues
public class AuthenticationController {

    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping("/register")
    public ApplicationUser registerUser(@RequestBody RegistrationDto body) {
        return authenticationService.registerUser(body.getUsername(), body.getPassword());
    }

    @PostMapping("/login")
    public LoginResponseDTO loginUser(@RequestBody RegistrationDto body) {
        return authenticationService.loginUser(body.getUsername(), body.getPassword());
    }
}
