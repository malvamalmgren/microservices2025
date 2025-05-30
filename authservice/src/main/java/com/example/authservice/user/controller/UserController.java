package com.example.authservice.user.controller;

import com.example.authservice.user.dto.RegistryDTO;
import com.example.authservice.entity.AppUser;
import com.example.authservice.user.UserRole;
import com.example.authservice.user.service.UserService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public String register(@RequestBody @Valid RegistryDTO registry) {
        AppUser user = new AppUser();
        user.setUsername(registry.getUsername());
        user.setPassword(registry.getPassword());
        user.setRole((UserRole.ROLE_USER));
        userService.addUser(user);
        return "User registered successfully";
    }
}
