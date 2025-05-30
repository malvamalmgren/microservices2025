package com.example.authservice.user.service;

import com.example.authservice.entity.AppUser;
import com.example.authservice.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;

@Service
@Transactional
public class UserService {
    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository,  PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public AppUser addUser(AppUser user) {
        if (userRepository.existsByUsername(user.getUsername()))
            throw new IllegalArgumentException("Username is taken.");

        log.info("Creating new user: {}", user.getUsername());
        if (user.getPassword() != null && !user.getPassword().isEmpty()) {
            String hashedPassword = passwordEncoder.encode(user.getPassword());
            user.setPassword(hashedPassword);
        } else {
            user.setPassword(null);
        }
        return userRepository.save(user);
    }
}
