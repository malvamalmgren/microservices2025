package com.example.authservice.user;

import com.example.authservice.RegistryDTO;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {

    UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

//    private AppUser getCurrentUser(Authentication auth) {
//        return userService.findUserByUsername(auth.getName());
//    }

    @PostMapping("/register")
    public String register(@RequestBody RegistryDTO registry) {
        AppUser user = new AppUser();
        user.setUsername(registry.getUsername());
        user.setPassword(registry.getPassword());
        user.setRole((UserRole.ROLE_USER));
        userService.addUser(user);
        return "User registered successfully";
    }
}
