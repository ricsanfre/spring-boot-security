package com.ricsanfre.security;

import com.ricsanfre.security.auth.AuthenticationService;
import com.ricsanfre.security.auth.RegisterRequest;
import com.ricsanfre.security.user.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(
			AuthenticationService authenticationService
	) {
		return args -> {

			RegisterRequest admin =
					RegisterRequest.builder()
							.firstName("Admin")
							.lastName("Admin")
							.email("admin@mail.com")
							.password("password")
							.role(Role.ADMIN)
							.build();

			System.out.println("ADMIN access token:" +
					authenticationService.register(admin).getAccessToken());

			RegisterRequest manager =
					RegisterRequest.builder()
							.firstName("Manager")
							.lastName("Manager")
							.email("manager@mail.com")
							.password("password")
							.role(Role.MANAGER)
							.build();

			System.out.println("MANAGER access token:" +
					authenticationService.register(manager).getAccessToken());


		};

	}
}
