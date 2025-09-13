package com.sqli.detector.securitygateway.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import java.time.Duration;

@Service
@Slf4j
public class IpThrottlingService {

    private final ReactiveRedisTemplate<String, String> redisTemplate;

    @Value("${sqli-detection.throttling.enabled:true}")
    private boolean enabled;
    @Value("${sqli-detection.throttling.max-attempts:5}")
    private int maxAttempts;
    @Value("${sqli-detection.throttling.time-window-minutes:1}")
    private int timeWindowMinutes;
    @Value("${sqli-detection.throttling.block-duration-minutes:15}")
    private int blockDurationMinutes;

    public IpThrottlingService(ReactiveRedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    private static final String KEY_PREFIX_ATTEMPTS = "sqli:attempts:";
    private static final String KEY_PREFIX_BLOCKED = "sqli:blocked:";

    /**
     * Checks if a given IP address is currently on the blocklist.
     */
    public Mono<Boolean> isBlocked(String ip) {
        if (!enabled) {
            return Mono.just(false);
        }
        return redisTemplate.hasKey(KEY_PREFIX_BLOCKED + ip);
    }

    /**
     * Records a failed attempt for an IP. If the number of attempts exceeds the
     * configured threshold, the IP is added to the blocklist.
     */
    public void recordFailedAttempt(String ip) {
        if (!enabled) {
            return;
        }

        String attemptKey = KEY_PREFIX_ATTEMPTS + ip;

        redisTemplate.opsForValue().increment(attemptKey)
                .flatMap(attempts -> {
                    if (attempts == 1) {
                        // This is the first attempt in the window, set the expiry
                        return redisTemplate.expire(attemptKey, Duration.ofMinutes(timeWindowMinutes))
                                .thenReturn(attempts);
                    }
                    return Mono.just(attempts);
                })
                .filter(attempts -> attempts >= maxAttempts)
                .flatMap(attempts -> {
                    // Threshold reached, block the IP
                    log.warn("Throttling threshold reached for IP {}. Blocking for {} minutes.", ip, blockDurationMinutes);
                    String blockKey = KEY_PREFIX_BLOCKED + ip;
                    return redisTemplate.opsForValue().set(blockKey, "blocked", Duration.ofMinutes(blockDurationMinutes));
                })
                .subscribe(); // Subscribe to execute the reactive chain
    }
}