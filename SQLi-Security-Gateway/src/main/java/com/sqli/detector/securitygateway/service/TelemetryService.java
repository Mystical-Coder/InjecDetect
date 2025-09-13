package com.sqli.detector.securitygateway.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sqli.detector.securitygateway.dto.Decision;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class TelemetryService {

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Logs the final decision made by the filter.
     * @param request The original server request.
     * @param payload The payload sent to the model service.
     * @param decision The decision object containing the action and score.
     */
    public void logDecision(ServerHttpRequest request, String payload, Decision decision) {
        try {
            ObjectNode logJson = objectMapper.createObjectNode();
            logJson.put("decision", decision.action().toString());
            logJson.put("score", String.format("%.4f", decision.score()));
            // Corrected: Use getMethod().name() to get the HTTP method string
            logJson.put("method", request.getMethod().name());
            logJson.put("uri", request.getURI().toString());
            logJson.put("payload", redactPii(payload));
            log.info("TELEMETRY_EVENT: {}", objectMapper.writeValueAsString(logJson));
        } catch (JsonProcessingException e) {
            log.error("Error generating telemetry JSON for decision event", e);
        }
    }

    /**
     * Logs failures that occur when calling the model service.
     * @param throwable The exception that was thrown.
     */
    public void logFailure(Throwable throwable) {
        try {
            ObjectNode logJson = objectMapper.createObjectNode();
            logJson.put("event", "MODEL_SERVICE_FAILURE");
            logJson.put("error", throwable.getMessage());
            log.error("TELEMETRY_EVENT: {}", objectMapper.writeValueAsString(logJson));
        } catch (JsonProcessingException e) {
            log.error("Error generating telemetry JSON for failure event", e);
        }
    }

    private String redactPii(String payload) {
        // Implement more sophisticated PII redaction logic here
        return payload.replaceAll("(?i)password=\\S+", "password=[REDACTED]");
    }
}