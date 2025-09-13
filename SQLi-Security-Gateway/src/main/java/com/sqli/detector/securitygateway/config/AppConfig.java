package com.sqli.detector.securitygateway.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import java.time.Duration;

@Configuration
public class AppConfig {


    @Bean
    @Primary
    public WebClient.Builder webClientBuilder(
            @Value("${sqli-detection.model-service-timeout-ms:2000}") int timeoutMs) {

        HttpClient httpClient = HttpClient.create()
                .responseTimeout(Duration.ofMillis(timeoutMs));

        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient)) // Apply the timeout setting
                .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(2 * 1024 * 1024));
    }

    @Bean
    public CacheManager cacheManager(@Value("${sqli-detection.cache.ttl-seconds}") int ttl,
                                     @Value("${sqli-detection.cache.max-size}") int maxSize) {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager("sqlDetectionCache");
        cacheManager.setCaffeine(Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofSeconds(ttl))
                .maximumSize(maxSize)
                .recordStats());
        return cacheManager;
    }
}

