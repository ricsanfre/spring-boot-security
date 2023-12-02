package com.ricsanfre.security.config;

import com.ricsanfre.security.token.Token;
import com.ricsanfre.security.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;
    @Override
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication) {

        final String jwt;
        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")){
            return;
        }
        // Get token: removing "Bearer " string
        jwt = authHeader.substring(7);

        // Find token in the DB
        Token storedToken = tokenRepository.findByToken(jwt).orElse(null);
        if (storedToken!=null) {
            // Revoke and expire the token
            storedToken.setRevoked(true);
            storedToken.setExpired(true);
            tokenRepository.save(storedToken);
        }
    }
}
