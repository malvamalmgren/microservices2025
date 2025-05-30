package com.example.quoteservice;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Random;

@RestController
@RequestMapping("/quotes")
public class QuoteController {
    private final Random random = new Random();

    private final String[] quotes = {
            "“In the middle of every difficulty lies opportunity.” – Albert Einstein",
            "“Be yourself; everyone else is already taken.” – Oscar Wilde",
            "“The best time to plant a tree was 20 years ago. The second best time is now.” – Chinese Proverb"
    };

    @GetMapping("/random")
    public String getQuote() {
        return quotes[random.nextInt(quotes.length)];
    }
}
