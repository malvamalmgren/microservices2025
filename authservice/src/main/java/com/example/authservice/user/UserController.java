package com.example.authservice.user;

import com.example.authservice.RegistryDTO;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

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
    public String register(@RequestParam String username, @RequestParam String password) {
        AppUser user = new AppUser();
        user.setUsername(username);
        user.setPassword(password);
        user.setRole((UserRole.ROLE_USER));
        userService.addUser(user);
        return "User registered successfully";
    }
}
