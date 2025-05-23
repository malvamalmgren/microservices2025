package com.example.jokeservice;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JokeController {

    @GetMapping("/secure")
    public String getSecureJoke() {
        return "Secure Joke Server, valid token";
    }

    @GetMapping("/public")
    public String getPublicJoke() {
        return "Public Joke Server";
    }
}
