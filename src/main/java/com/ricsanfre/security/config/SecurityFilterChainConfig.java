package com.ricsanfre.security.config;

import com.ricsanfre.security.user.Permissions;
import com.ricsanfre.security.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.ricsanfre.security.jwt.JwtAuthenticationFilter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
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
                // Http Request authorization
                .authorizeHttpRequests((authorize) -> {
                    authorize.requestMatchers(
                                    HttpMethod.POST,
                                    "/api/v1/auth/**")
                            .permitAll();
                    authorize.requestMatchers("/api/v1/management/**")
                            .hasAnyRole(
                                    Role.ADMIN.name(),
                                    Role.MANAGER.name());
                    authorize.requestMatchers(
                                    HttpMethod.GET,
                                    "/api/v1/management/**")
                            .hasAnyAuthority(
                                    Permissions.ADMIN_READ.name(),
                                    Permissions.MANAGER_READ.name());
                    authorize.requestMatchers(
                                    HttpMethod.POST,
                                    "/api/v1/management/**")
                            .hasAnyAuthority(
                                    Permissions.ADMIN_CREATE.name(),
                                    Permissions.MANAGER_CREATE.name());
                    authorize.requestMatchers(
                                    HttpMethod.PUT,
                                    "/api/v1/management/**")
                            .hasAnyAuthority(
                                    Permissions.ADMIN_UPDATE.name(),
                                    Permissions.MANAGER_UPDATE.name());
                    authorize.requestMatchers(
                                    HttpMethod.DELETE,
                                    "/api/v1/management/**")
                            .hasAnyAuthority(
                                    Permissions.ADMIN_DELETE.name(),
                                    Permissions.MANAGER_DELETE.name());
                    /*
                    authorize.requestMatchers("/api/v1/admin/**")
                            .hasRole(
                                    Role.ADMIN.name());
                    authorize.requestMatchers(
                                    HttpMethod.GET,
                                    "/api/v1/admin/**")
                            .hasAuthority(
                                    Permissions.ADMIN_READ.name());
                    authorize.requestMatchers(
                                    HttpMethod.POST,
                                    "/api/v1/admin/**")
                            .hasAuthority(
                                    Permissions.ADMIN_CREATE.name());
                    authorize.requestMatchers(
                                    HttpMethod.PUT,
                                    "/api/v1/admin/**")
                            .hasAuthority(
                                    Permissions.ADMIN_UPDATE.name());
                    authorize.requestMatchers(
                                    HttpMethod.DELETE,
                                    "/api/v1/admin/**")
                            .hasAuthority(
                                    Permissions.ADMIN_DELETE.name());
                    */
                    // Enable access to API docs endpoints
                    authorize.requestMatchers(
                                    "/v3/api-docs",
                                    "/v3/api-docs/**",
                                    "/swagger-resources",
                                    "/swagger-resources/**",
                                    "/configuration/ui",
                                    "/configuration/security",
                                    "/swagger-ui/**",
                                    "/swagger-ui.html")
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
                });
        return http.build();
    }
}
