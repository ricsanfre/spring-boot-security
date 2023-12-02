package com.ricsanfre.security.jwt;

<<<<<<< HEAD
=======
import com.ricsanfre.security.token.Token;
import com.ricsanfre.security.token.TokenRepository;
>>>>>>> ebd6bf9 (Securing API with JWT tokens and logout implementation)
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@AllArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
<<<<<<< HEAD
=======
    private final TokenRepository tokenRepository;
>>>>>>> ebd6bf9 (Securing API with JWT tokens and logout implementation)
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String jwt;
        final String userEmail;
        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
        // Get token: removing "Bearer " string
        jwt = authHeader.substring(7);
        // Get user email from token
        userEmail = jwtService.getSubject(jwt);
        if (userEmail !=null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Get User details from DB
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
<<<<<<< HEAD
            // Check if token is valid
            if (jwtService.isValidToken(jwt, userDetails)) {
=======
            // Check if the token is in DB
            boolean isValidToken = tokenRepository.findByToken(jwt)
                    .map(token -> !token.isExpired() && !token.isRevoked())
                    .orElse(false);

            // Check if token is valid
            if (jwtService.isValidToken(jwt, userDetails) && isValidToken) {
>>>>>>> ebd6bf9 (Securing API with JWT tokens and logout implementation)
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                // Update security context
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request,response);

    }
}
