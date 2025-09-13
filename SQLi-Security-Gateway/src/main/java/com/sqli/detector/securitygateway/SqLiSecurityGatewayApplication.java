package com.sqli.detector.securitygateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching // Enables Spring's caching capabilities
public class SqLiSecurityGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(SqLiSecurityGatewayApplication.class, args);
    }

}
