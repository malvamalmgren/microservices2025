package com.example.authservice.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<AppUser, Long> {
    boolean existsByUsername(String userName);

    Optional<AppUser> findByUsername(String userName);
    List<AppUser> findByRole(UserRole role);
}
