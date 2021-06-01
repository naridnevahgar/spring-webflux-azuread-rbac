package com.rs.AzureADIntegrationDemo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class AdAuthService {

    @PreAuthorize("hasRole('admin')")
    public Mono<String> greetAdmins() {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .map(auth -> (Jwt) auth.getPrincipal())
                .map(token -> "Hi " + token.getClaimAsString("preferred_username"));
    }
}
