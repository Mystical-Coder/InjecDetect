package com.sqli.detector.securitygateway.dto;

/**
 * The request body sent to the Python model service.
 * @param payload The combined request data (path, query, body).
 */

public record ModelRequest(String payload) {}
