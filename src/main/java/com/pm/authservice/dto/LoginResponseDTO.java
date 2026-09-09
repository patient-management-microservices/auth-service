package com.pm.authservice.dto;

public record LoginResponseDTO (
    String accessToken,
    String refreshToken,
    String tokenType,
    long expiresIn
) {}
