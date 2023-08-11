package com.unknowncoder.services;

import com.unknowncoder.models.ApplicationUser;
import com.unknowncoder.models.LoginResponseDTO;
import com.unknowncoder.models.Role;
import com.unknowncoder.repository.RoleRepository;
import com.unknowncoder.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Service // helps spring to create this class as a bean for us
@Transactional // transaction between our database and application , what it does is we r going to treat every single method
// inside this authentication service as a single transaction , that way if we make multiple database calls and changing
// multiple pieces in the database and things of that sort if a method ends up failing or something along those lines
// its going to go ahead and cancel out that transaction and the database is'nt going to be messed with
public class AuthenticationService {

    @Autowired // dirty and fast, elegant way is constructor injection
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager; // this is going to determine whether or not we want to go ahead a make a jwt token
    // this is going to grab the instance that we set up in our configuration autowired
    // we need a token serves that way after we know that we r authenticated to log in we can actually go ahead and generate
    // that token
    // then we also need that token service that way afer we know that we r authenticated to login we can acutally go ahead and
    // generate that token for the user
    @Autowired
    private TokenService tokenService;


    public ApplicationUser registerUser(String username, String password) {
        String encodedPassword = passwordEncoder.encode(password);
        Role userRole = roleRepository.findByAuthority("USER").get();
        Set<Role> authorities = new HashSet<>();
        authorities.add(userRole);
        return userRepository.save(new ApplicationUser(0, username, encodedPassword, authorities));
    }

    public LoginResponseDTO loginUser(String username, String password) {

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            // basically what its going to do is whenever we send a request for a login user
            // user is going to  pass in the username and password to this authentication manager
            // its going to use our user details service that we setup earlier , grab the user and that
            // username doesn't exist its going to throw an exception or if the username does exist and then the password
            // exists it will create the spit out new token otherwise throw an exception
            // auth and authentication is just a generic token or generic authentication object so this new
            // UsernamePasswordAuthenticationToken is a more specific version of authentication or token service method
            //
            String token = tokenService.generateJwt(authentication);

            return new LoginResponseDTO(userRepository.findByUsername(username).get(), token);
        } catch (AuthenticationException e) {
            return new LoginResponseDTO(null, "");
        }

        // purpose of this method is its going to take in the authentication manager
        // its going to look for username and password and make sure that they are proper
        // and is going to generate something called an authentication token send that over to our token service
        // and generate the token and spit it out


    }
}
