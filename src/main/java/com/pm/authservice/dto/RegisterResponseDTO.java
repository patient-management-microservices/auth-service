package com.pm.authservice.dto;

import com.pm.authservice.enums.Role;

import java.util.UUID;

public record RegisterResponseDTO(
        UUID id,
        String email,
        Role role
) {}
