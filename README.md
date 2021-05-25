# Spring WebFlux Reactive App RBAC with Azure AD

This demo explains how to get Azure AD JWT token based RBAC implementation for a Spring WebFlux reactive app. 

Microsoft provides a maven dependency, `azure-active-directory-spring-boot-starter` for integrating Azure AD authenticaiton into Spring based applications. However, this dependency expects the servlet dependencies to be present and hence does not work with reactive WebFlux based applications. 

This demo leverages the spring native `spring-boot-starter-security` dependency along with `spring-security-oauth2-resource-server` and `spring-security-oauth2-jose` to implement a reactive spring OAuth2.0 resource server backed by Azure AD. 

## Azure Setup

- Register an application on Azure AD and capture the client id of your application
- Keep your tenant ID handy

## Spring Setup

### Maven Dependencies

Add the below maven dependencies to your project:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-webflux</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-resource-server</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-jose</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

### Configure application to use Azure AD provider

In `application.yml`, initialize spring security resource server to use Azure AD as the authorization server by setting `spring.security.oauth2.resourceserver.jwt.issuer-uri` to the issuer URI of your app. 

To find your issuer URI,
- Use the `iss` claim in your JWT token
- From your application endpoints, hit the open id metadata document URL. Hit it and find the `issuer_uri` property
- Build it yourself: `https://login.microsoftonline.com/<your-tenant-id>/v2.0` 

### Enable Spring WebFlux Security

- Use `@EnableWebFluxSecurity` to enable Spring WebFlux reactive security
- Optionally, use `@EnableReactiveMethodSecurity` to enable method level security checks, including pre/post authorize annotations

At this point, your application is fully secured by Azure AD based RBAC. However, this is incomplete. With the above configurations, Spring only checks for the `iss` claim i.e., the JWT token's issuer and `exp` claim i.e., the JWT token's expiry. 

This is by design, as Spring allows plugging in multiple auth providers and implementations. 

### Customizing Security Checks

#### Validate the Token's audience

The `aud` claim i.e., to which application was the token generated for, is set inside this claim by Azure AD. 

We have captured the client id from Azure AD as part of the Azure setups.

So, we can supply a custom JWT token validator which can check this claim.

```java
ReactiveJwtDecoder jwtDecoder() {
    NimbusReactiveJwtDecoder jwtDecoder = (NimbusReactiveJwtDecoder)
            ReactiveJwtDecoders.fromIssuerLocation(issuerUri);

    OAuth2TokenValidator<Jwt> tokenValidator = new DelegatingOAuth2TokenValidator<Jwt>(
            JwtValidators.createDefaultWithIssuer(issuerUri),
            new JwtClaimValidator<List<String>>("aud", (aud) -> {
                return aud != null && aud.contains(clientId);
            }));

    jwtDecoder.setJwtValidator(tokenValidator);

    return jwtDecoder;
}
```

The `clientId` parameter can be maintained as an externalized configuration. 

#### Validate the Token based on AppRoles instead of Scope

By default, Spring maps the `scp` claims into `GrantedAuthorities` which informs the application code about the list of permissions granted as part of the token. 

If the application registered custom application roles in Azure AD, `roles` claim would be appended specific to each user by Azure AD. 

If the application needs these roles and intends to implement method level authorization, typically via `@PreAuthorize("hasRole('<your role>')"`, supply your custom authority extractor like below: 

```java
Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesExtractor() {
    JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
    jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter
            ((jwt) -> {
                Collection<?> authorities = (Collection<?>)
                        jwt.getClaims().getOrDefault("roles", Collections.emptyList());

                return authorities.stream()
                        .map(Object::toString)
                        .map(role -> "ROLE_".concat(role))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
            });
    return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
}
```

_Note: for method level authorization, `@EnableReactiveMethodSecurity` has to be placed inside application components_

Now, for every request, the JWT token would be converted into an `AuthenticatedPrincipal` and can be used in every layer of your application to perform pre authorization.

```java
@PreAuthorize("hasRole('admin')")
public Mono<ServerResponse> handleGreet(ServerRequest request) {

    return ServerResponse.ok()
            .contentType(MediaType.TEXT_PLAIN)
            .body(BodyInserters.fromProducer(adAuthService.greetAdmins(), String.class));
}
```