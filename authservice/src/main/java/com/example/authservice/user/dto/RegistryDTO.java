package com.example.authservice.user.dto;

import jakarta.validation.constraints.NotBlank;

public class RegistryDTO {
    @NotBlank
    private String username;
    @NotBlank
    private String password;

    public RegistryDTO(String username, String password) {
        this.username = username;
        this.password = password;
    }
    public RegistryDTO() {
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
