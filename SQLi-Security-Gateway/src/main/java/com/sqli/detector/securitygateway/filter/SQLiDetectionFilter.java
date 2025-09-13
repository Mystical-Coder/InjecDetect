package com.sqli.detector.securitygateway.filter;

import com.sqli.detector.securitygateway.dto.Action;
import com.sqli.detector.securitygateway.dto.Decision;
import com.sqli.detector.securitygateway.dto.ModelRequest;
import com.sqli.detector.securitygateway.dto.ModelResponse;
import com.sqli.detector.securitygateway.service.TelemetryService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4JCircuitBreakerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.Callable;

@Slf4j
@Component
public class SQLiDetectionFilter implements GlobalFilter, Ordered {


    private final WebClient webClient;
    private final ReactiveResilience4JCircuitBreakerFactory circuitBreakerFactory;
    private final TelemetryService telemetryService;
    private final Cache sqlCache;

    // --- Configurable Properties ---
    @Value("${sqli-detection.enabled:true}")
    private boolean enabled;
    @Value("${sqli-detection.fail-open:true}")
    private boolean failOpen;
    @Value("${sqli-detection.thresholds.block}")
    private double blockThreshold;
    @Value("${sqli-detection.thresholds.monitor}")
    private double monitorThreshold;
    @Value("${sqli-detection.model-service-timeout-ms:2000}")
    private int modelServiceTimeoutMs;

    public SQLiDetectionFilter(WebClient.Builder webClientBuilder,
                               ReactiveResilience4JCircuitBreakerFactory cbFactory,
                               TelemetryService telemetryService,
                               CacheManager cacheManager,
                               @Value("${sqli-detection.model-service-url}") String modelServiceUrl) {
        this.webClient = webClientBuilder.baseUrl(modelServiceUrl).build();
        this.circuitBreakerFactory = cbFactory;
        this.telemetryService = telemetryService;
        this.sqlCache = cacheManager.getCache("sqlDetectionCache");
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!enabled) {
            return chain.filter(exchange);
        }

        ServerHttpRequest request = exchange.getRequest();

        return DataBufferUtils.join(request.getBody())
                .flatMap(dataBuffer -> {
                    String body = dataBuffer.toString(StandardCharsets.UTF_8);
                    DataBufferUtils.release(dataBuffer);

                    ServerHttpRequest mutatedRequest = new ServerHttpRequestDecorator(request) {
                        @Override
                        public Flux<DataBuffer> getBody() {
                            return Flux.just(exchange.getResponse().bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8)));
                        }
                    };
                    ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();

                    String payload = String.format("PATH: %s, QUERY: %s, BODY: %s",
                            request.getURI().getPath(), request.getURI().getQuery(), body);
                    String payloadHash = createHash(payload);

                    Callable<Mono<Decision>> modelCall = () -> callModelService(payload);
                    Mono<Decision> decisionMono = Mono.fromCallable(() -> sqlCache.get(payloadHash, modelCall))
                            .flatMap(result -> (Mono<Decision>) result);

                    return decisionMono.flatMap(decision -> {
                        telemetryService.logDecision(request, payload, decision);

                        switch (decision.action()) {
                            case BLOCK:
                                log.warn("BLOCKING request due to high SQLi score: {}", decision.score());
                                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                                return exchange.getResponse().setComplete();
                            case MONITOR:
                                log.info("MONITORING request with medium SQLi score: {}", decision.score());
                                return chain.filter(mutatedExchange);
                            default:
                                return chain.filter(mutatedExchange);
                        }
                    });
                });
    }

    private Mono<Decision> callModelService(String payload) {
        var circuitBreaker = circuitBreakerFactory.create("modelService");

        Mono<ModelResponse> responseMono = webClient.post()
                .uri("/predict")
                .bodyValue(new ModelRequest(payload))
                .retrieve()
                .bodyToMono(ModelResponse.class)
                .timeout(Duration.ofMillis(modelServiceTimeoutMs));

        return responseMono
                .transform(it -> circuitBreaker.run(it, this::handleFailure))
                .map(this::evaluateScore);
    }

    /**
     * Fallback method for the circuit breaker.
     * Must return a Mono of the same type as the one it's protecting (Mono<ModelResponse>).
     */
    private Mono<ModelResponse> handleFailure(Throwable throwable) {
        log.error("SQLi model service call failed: {}", throwable.getMessage());
        telemetryService.logFailure(throwable);
        if (failOpen) {
            log.warn("Failing open. Allowing request to pass by returning a safe score.");
            // Return a ModelResponse with a safe score.
            // The subsequent .map(this::evaluateScore) will turn this into an ALLOW decision.
            return Mono.just(new ModelResponse(0.0));
        } else {
            log.error("Failing closed. Propagating error to block request.");
            // Propagate the original error. This will terminate the reactive chain with an error,
            // resulting in a 500 response, effectively blocking the request.
            return Mono.error(throwable);
        }
    }

    private Decision evaluateScore(ModelResponse response) {
        double score = response.sqlInjectionScore();
        if (score >= blockThreshold) {
            return new Decision(Action.BLOCK, score);
        } else if (score >= monitorThreshold) {
            return new Decision(Action.MONITOR, score);
        } else {
            return new Decision(Action.ALLOW, score);
        }
    }

    private String createHash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Could not create hash for caching", e);
        }
    }

    @Override
    public int getOrder() {
        return -100;
    }
}

