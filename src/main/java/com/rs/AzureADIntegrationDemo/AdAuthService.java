package com.rs.AzureADIntegrationDemo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class AdAuthService {

    @PreAuthorize("hasRole('admin')")
    public Mono<String> greetAdmins() {
        return Mono.just("hello admin!");
    }
}
