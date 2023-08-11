package com.unknowncoder;

import com.unknowncoder.models.ApplicationUser;
import com.unknowncoder.models.Role;
import com.unknowncoder.repository.RoleRepository;
import com.unknowncoder.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Set;

@SpringBootApplication
public class AuthenticatedBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthenticatedBackendApplication.class, args);
	}

	@Bean
	CommandLineRunner run(RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder passwordEncoder){
		return args -> {
			// what if we turn off the create drop and then turn it into update
			// so we r gonna need some way to check to see if something exists in there
			// and if the for example if the admin role already exists that means the user role must exist
			// and also the add-on must exist because this command line runner has run so you want to go ahead
			// and to check to see if this exists so we can do that with a simple if statement
			// as findByAuthority is going to return an optional we use isPresent(), if we find then just return and exit out of this method
			if (roleRepository.findByAuthority("ADMIN").isPresent()) return;
			Role adminRole = roleRepository.save(new Role("ADMIN"));
			roleRepository.save(new Role("USER"));
			Set<Role> roles = new HashSet<>();
			roles.add(adminRole);
			ApplicationUser admin = new ApplicationUser(1, "admin", passwordEncoder.encode("password"), roles);
			userRepository.save(admin);
		};
	}

}
