package com.rs.AzureADIntegrationDemo;

import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
public class AdAuthEpHandler {

    private final AdAuthService adAuthService;

    public AdAuthEpHandler(AdAuthService adAuthService) {
        this.adAuthService = adAuthService;
    }

    @PreAuthorize("hasRole('admin')")
    public Mono<ServerResponse> handleGreet(ServerRequest request) {

        return ServerResponse.ok()
                .contentType(MediaType.TEXT_PLAIN)
                .body(BodyInserters.fromProducer(adAuthService.greetAdmins(), String.class));
    }
}
