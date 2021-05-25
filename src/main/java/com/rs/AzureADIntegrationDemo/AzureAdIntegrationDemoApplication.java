package com.rs.AzureADIntegrationDemo;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@SpringBootApplication
@Slf4j
public class AzureAdIntegrationDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(AzureAdIntegrationDemoApplication.class, args);
	}

	@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
	private String issuerUri;

	@Value("${spring.security.oauth2.resourceserver.jwt.client-id}")
	private String clientId;

	@Bean
	SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
		http.authorizeExchange(exchanges -> exchanges.anyExchange().authenticated())
				.oauth2ResourceServer()
				.jwt()
				.jwtDecoder(jwtDecoder())
				.jwtAuthenticationConverter(grantedAuthoritiesExtractor())
		;
		return http.build();
	}

	ReactiveJwtDecoder jwtDecoder() {
		NimbusReactiveJwtDecoder jwtDecoder = (NimbusReactiveJwtDecoder)
				ReactiveJwtDecoders.fromIssuerLocation(issuerUri);

		OAuth2TokenValidator<Jwt> tokenValidator = new DelegatingOAuth2TokenValidator<Jwt>(
				JwtValidators.createDefaultWithIssuer(issuerUri),
				new JwtClaimValidator<List<String>>("aud", (aud) -> {
					log.info("Validating JWT token, {} with {}", aud, clientId);
					return aud != null && aud.contains(clientId);
				}));

		jwtDecoder.setJwtValidator(tokenValidator);

		return jwtDecoder;
	}

	Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesExtractor() {
		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter
				((jwt) -> {
					Collection<?> authorities = (Collection<?>)
							jwt.getClaims().getOrDefault("roles", Collections.emptyList());

					return authorities.stream()
							.map(Object::toString)
							.map(role -> "ROLE_".concat(role))	// TODO: seriously? find a better way
							.map(SimpleGrantedAuthority::new)
							.collect(Collectors.toList());
				});
		return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
	}

}
