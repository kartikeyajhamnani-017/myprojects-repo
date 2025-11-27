package com.kartikeyajhamnani_017.LedgerEzBackend.controller;


import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Main Spring Security configuration class.
 * This class configures how HTTP requests are secured.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    /**
     * Defines the security filter chain that applies to all HTTP requests.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Disable CSRF (Cross-Site Request Forgery)
                // We are stateless, so we don't need this protection
                .csrf(csrf -> csrf.disable())

                // Define authorization rules
                .authorizeHttpRequests(auth -> auth
                        // Whitelist our public authentication endpoints
                        .requestMatchers("/api/v1/auth/**").permitAll()
                        // Any other request must be authenticated
                        .anyRequest().authenticated()
                )

                // Configure session management to be stateless
                // Spring Security will not create or use HTTP sessions
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Set our custom authentication provider (from AppConfig)
                .authenticationProvider(authenticationProvider)

                // Add our custom JWT filter to run before the standard
                // UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}