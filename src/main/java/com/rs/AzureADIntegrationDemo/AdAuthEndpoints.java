package com.rs.AzureADIntegrationDemo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

@Configuration
public class AdAuthEndpoints {

    @Bean
    public RouterFunction<ServerResponse> authenticate(AdAuthEpHandler epHandler) {
        return RouterFunctions.route(RequestPredicates.GET("/greet").and(RequestPredicates.accept(MediaType.ALL)), epHandler::handleGreet);
    }
}