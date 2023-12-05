package com.ricsanfre.security.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;

@OpenAPIDefinition(
        info = @Info(
                contact =  @Contact(
                        name="Ricardo",
                        email = "ricardo@mail.com",
                        url = "https://ricsanfre.com"
                ),
                description = "Open API documentation for Spring Security",
                title = "Open API Specification - Demo Spring-Boot App",
                version = "1.0",
                license = @License(
                        name = "MIT",
                        url = "https://anUrl.com"
                ),
                termsOfService = "Terms of Service..."
        ),
        servers = {
                @Server(
                        description = "Dev environment",
                        url = "http://localhost:8080"
                ),
                @Server(
                        description = "Prod environment",
                        url = "https://ricsanfre.com"
                )
        },
        security = {
                @SecurityRequirement(name = "bearerAuth")
        }
)
@SecurityScheme(
        name = "bearerAuth",
        description = "JWT Auth description",
        scheme = "bearer",
        type = SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        in = SecuritySchemeIn.HEADER
)
public class OpenApiConfig {

}
