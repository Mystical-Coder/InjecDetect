package com.sqli.detector.securitygateway.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ModelResponse(@JsonProperty("sql_injection_score") double sqlInjectionScore) {}

