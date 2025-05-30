package com.example.jokeservice;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Random;

@RestController
@RequestMapping("/jokes")
public class JokeController {
    private final Random random = new Random();

    private final String[] jokes = {
            "Why don't scientists trust atoms? Because they make up everything!",
            "I told my computer I needed a break, and it said 'No problem – I'll go to sleep.'",
            "Why did the scarecrow win an award? Because he was outstanding in his field!"
    };

    @GetMapping("/random")
    public String getJoke() {
        return jokes[random.nextInt(jokes.length)];
    }
}
