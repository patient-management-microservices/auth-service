package com.pm.authservice.service;

import com.pm.authservice.dto.LoginRequestDTO;
import com.pm.authservice.dto.LoginResponseDTO;
import com.pm.authservice.dto.RegisterRequestDTO;
import com.pm.authservice.dto.RegisterResponseDTO;
import com.pm.authservice.enums.Role;
import com.pm.authservice.exception.EmailAlreadyExistsException;
import com.pm.authservice.model.User;
import com.pm.authservice.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class AuthService {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthService(
            UserService userService,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil
    ) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    public Optional<LoginResponseDTO> authenticate(LoginRequestDTO loginRequestDTO) {
        String normalizedEmail = loginRequestDTO.email().trim().toLowerCase();

        return userService
                .findByEmail(normalizedEmail)
                .filter(user -> passwordEncoder.matches(loginRequestDTO.password(), user.getPasswordHash()))
                .map(user -> new LoginResponseDTO(
                        jwtUtil.generateToken(user.getId(), user.getEmail(), user.getRole()),
                        "Bearer",
                        jwtUtil.getExpirationMs() / 1000
                ));
    }

    @Transactional
    public RegisterResponseDTO register(RegisterRequestDTO registerRequestDTO) {
        String normalizedEmail = registerRequestDTO.email().trim().toLowerCase();

        if (userService.existsByEmail(normalizedEmail)) {
            throw new EmailAlreadyExistsException(normalizedEmail);
        }

        User savedUser = userService.save(User.builder()
                .email(normalizedEmail)
                .passwordHash(passwordEncoder.encode(registerRequestDTO.password()))
                .role(Role.USER)
                .build());

        return new RegisterResponseDTO(savedUser.getId(), savedUser.getEmail(), savedUser.getRole());
    }

    public boolean validateToken(String token) {
        try {
            jwtUtil.validateToken(token);
            return true;
        } catch (JwtException je) {
            return false;
        }
    }

}
