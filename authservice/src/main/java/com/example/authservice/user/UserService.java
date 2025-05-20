package com.example.authservice.user;

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

    public AppUser findUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("User with id " + id + " not found"));
    }

    public AppUser findUserByUserName(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new NoSuchElementException("User with username " + username + " not found"));
    }

    //_____________

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

//    public AppUser updateUser(Long userId, Map<String, Object> updates) {
//        AppUser existingUser = findUserById(userId);
//
//        if (updates.containsKey("userEmail")) {
//            String newEmail = updates.get("userEmail").toString();
//            Optional<AppUser> userByEmail = userRepository.findByUserEmail(newEmail);
//            if (userByEmail.isPresent() && !userByEmail.get().getUserId().equals(userId)) {
//                throw new AlreadyExistsException("Account with given email already exists.");
//            }
//        }
//
//        if (updates.containsKey("userName")) {
//            String newUserName = updates.get("userName").toString();
//            Optional<AppUser> userByName = userRepository.findByUserName(newUserName);
//            if (userByName.isPresent() && !userByName.get().getUserId().equals(userId)) {
//                throw new AlreadyExistsException("Username is taken.");
//            }
//        }
//
//        log.info("Partially updating user: {}", existingUser.getUserName());
//        if (updates.containsKey("userFullName")) {
//            existingUser.setUserFullName((String) updates.get("userFullName"));
//        }
//        if (updates.containsKey("userName")) {
//            existingUser.setUserName((String) updates.get("userName"));
//        }
//        if (updates.containsKey("userEmail")) {
//            existingUser.setUserEmail((String) updates.get("userEmail"));
//        }
//        if (updates.containsKey("userLocation")) {
//            existingUser.setUserLocation((String) updates.get("userLocation"));
//        }
//        if (updates.containsKey("userRole")) {
//            Object roleObj = updates.get("userRole");
//            if (roleObj instanceof String roleStr) {
//                existingUser.setUserRole(UserRole.valueOf(roleStr));
//            } else if (roleObj instanceof UserRole roleEnum) {
//                existingUser.setUserRole(roleEnum);
//            }
//        }
//        if (updates.containsKey("userAuthProvider")) {
//            existingUser.setUserAuthProvider((String) updates.get("userAuthProvider"));
//        }
//
//        return userRepository.save(existingUser);
//    }

    public void deleteUserById(Long userId) {
        if (!userRepository.existsById(userId)) {
            throw new NoSuchElementException("User with id " + userId + " not found");
        }
        log.info("Deleting user with id: {}", userId);
        userRepository.deleteById(userId);
    }
}
