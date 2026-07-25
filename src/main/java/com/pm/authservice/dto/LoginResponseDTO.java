package com.pm.authservice.dto;

public record LoginResponseDTO (
    String token,
    String tokenType,
    long expiresIn
) {}
