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

    /**
     * Configures the WebClient bean used to communicate with the model service.
     * It includes a configurable timeout for resilience.
     * @param timeoutMs The response timeout in milliseconds, read from application.yml.
     * @return A configured WebClient.Builder instance.
     */
    @Bean
    @Primary // Ensures this bean is used over any default beans
    public WebClient.Builder webClientBuilder(
            @Value("${sqli-detection.model-service-timeout-ms:2000}") int timeoutMs) {

        // Configure the underlying HttpClient to set the response timeout
        HttpClient httpClient = HttpClient.create()
                .responseTimeout(Duration.ofMillis(timeoutMs));

        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient)) // Apply the timeout setting
                .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(2 * 1024 * 1024));
    }

    /**
     * Configures the Caffeine cache manager for caching model predictions.
     * @param ttl The time-to-live for cache entries in seconds.
     * @param maxSize The maximum number of entries to store in the cache.
     * @return A configured CacheManager instance.
     */
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

