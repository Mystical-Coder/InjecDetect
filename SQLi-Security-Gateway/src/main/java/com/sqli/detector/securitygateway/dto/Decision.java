package com.sqli.detector.securitygateway.dto;


import javax.swing.*;

/**
 * Represents the final decision made by the filter.
 * @param action The action to take (ALLOW, BLOCK, MONITOR).
 * @param score The score received from the model.
 */
public record Decision(Action action, double score) {}
