package com.ricsanfre.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.ricsanfre.security.jwt.JwtAuthenticationFilter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityFilterChainConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutService logoutService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                /*
                Disabling CSRF (Cross Site Request Forgery)   - We are not using HTML Forms
                https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html#disable-csrf
                */
                .csrf((csrf) -> csrf.disable())
                // Cors config
                .cors(Customizer.withDefaults())
                // Authorize registerCustomer API without requiring authentication
                .authorizeHttpRequests((authorize) -> {
                    authorize.requestMatchers(
                                    HttpMethod.POST,
                                    "/api/v1/auth/**")
                            .permitAll();
                    authorize.requestMatchers(
                                    HttpMethod.GET,
                                    "/actuator/**")
                            .permitAll();
                    authorize.anyRequest().authenticated();
                })
                // Specify Stateless sessions. Each request need to be authenticated
                .sessionManagement((session) ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authenticationProvider(authenticationProvider)
                // Add JWT Filter before UsernamePasswordAuthenticationFilter (used for form based authentication)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                //.exceptionHandling((httpSecurityExceptionHandlingConfigurer) ->
                //        httpSecurityExceptionHandlingConfigurer.authenticationEntryPoint(authenticationEntryPoint));
                // Logout configuration: Logout endpoint and Handler
                .logout((logout) -> {
                    logout.logoutUrl("/api/v1/auth/logout");
                    logout.addLogoutHandler(logoutService);
                    logout.logoutSuccessHandler((request, response, authentication) -> {
                        SecurityContextHolder.clearContext();
                    });
                } );
        return http.build();
    }
}
