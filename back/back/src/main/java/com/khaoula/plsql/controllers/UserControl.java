package com.khaoula.plsql.controllers;

import java.util.HashSet;



import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.khaoula.plsql.exception.TokenRefreshException;
import com.khaoula.plsql.models.ERole;
import com.khaoula.plsql.models.RefreshToken;
import com.khaoula.plsql.models.Role;
import com.khaoula.plsql.models.User;
import com.khaoula.plsql.payload.request.LoginRequest;
import com.khaoula.plsql.payload.request.SignupRequest;
import com.khaoula.plsql.payload.request.TokenRefreshRequest;
import com.khaoula.plsql.payload.response.JwtResponse;
import com.khaoula.plsql.payload.response.MessageResponse;
import com.khaoula.plsql.payload.response.TokenRefreshResponse;
import com.khaoula.plsql.repository.RoleRepository;
import com.khaoula.plsql.repository.UserRepository;
import com.khaoula.plsql.security.jwt.JwtUtils;
import com.khaoula.plsql.services.RefreshTokenService;
import com.khaoula.plsql.services.UserDetailsImpl;

import org.springframework.web.bind.annotation.*;



@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class UserControl {
  @Autowired
  AuthenticationManager authenticationManager;

  @Autowired
  UserRepository userRepository;

  @Autowired
  RoleRepository roleRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;

  @Autowired
  RefreshTokenService refreshTokenService;
  
  // Login controller (login page)
  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager
        .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);

    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
    
    //Creating a new Jwt token
    String jwt = jwtUtils.generateJwtToken(userDetails);

    List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
        .collect(Collectors.toList());
    // Creating a new RefreshToken
    RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());
    
    // Returning a response the front (jwtResponse)
    return ResponseEntity.ok(new JwtResponse(jwt, refreshToken.getToken(), userDetails.getId(),
        userDetails.getUsername(), userDetails.getEmail(), roles));
  }
  
  // Adding a new User
  @PostMapping("/signup")
  public ResponseEntity<MessageResponse> registerUser(@Valid @RequestBody SignupRequest signUpRequest ) {
      // Checking if the username exists
      if (userRepository.existsByUsername(signUpRequest.getUsername())) {
          return ResponseEntity.badRequest().body(new MessageResponse("Erreur: Nom d'utilisateur déjà existe!"));
      }
      
      // Checking if the username field is empty or not + checking username length
      if (Objects.isNull(signUpRequest.getUsername()) || signUpRequest.getUsername().length() < 4) {
          return ResponseEntity.badRequest().body(new MessageResponse("Erreur: Nom d'utilisateur doit être plus que 4 caractères!"));
      }
      
      // Checking if the email exists
      if (userRepository.existsByEmail(signUpRequest.getEmail())) {
          return ResponseEntity.badRequest().body(new MessageResponse("Erreur: Email déjà existe!"));
      }
      
      // Checking if the password field is empty or not + checking password length
      if (Objects.isNull(signUpRequest.getPassword()) || signUpRequest.getPassword().length() < 6) {
          return ResponseEntity.badRequest().body(new MessageResponse("Erreur: Mot de passe doit être plus que 6 caractères!"));
      }

      // Create a new user's account
      User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(),
          encoder.encode(signUpRequest.getPassword()));

      Set<String> strRoles = signUpRequest.getRole();
      Set<Role> roles = new HashSet<>();

      if (strRoles == null) {
          Role userRole = roleRepository.findByName(ERole.Client)
              .orElseThrow(() -> new RuntimeException("Erreur: Role is not found."));
          roles.add(userRole);
      } else {
          strRoles.forEach(role -> {
              switch (role) {
                  case "Admin":
                      Role adminRole = roleRepository.findByName(ERole.Admin)
                          .orElseThrow(() -> new RuntimeException("Erreur: Role is not found."));
                      roles.add(adminRole);
                      break;
                  case "Livreur":
                      Role modRole = roleRepository.findByName(ERole.Livreur)
                          .orElseThrow(() -> new RuntimeException("Erreur: Role is not found."));
                      roles.add(modRole);
                      break;
                  default:
                      Role userRole = roleRepository.findByName(ERole.Client)
                          .orElseThrow(() -> new RuntimeException("Erreur: Role is not found."));
                      roles.add(userRole);
              }
          });
      }

      // Set the roles for the user
      user.setRoles(roles);
      userRepository.save(user);

      return ResponseEntity.ok(new MessageResponse("Inscription avec succés!"));
  }
  
  
  @PostMapping("/refreshtoken")
  public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest request) {
    String requestRefreshToken = request.getRefreshToken();

    return refreshTokenService.findByToken(requestRefreshToken)
        .map(refreshTokenService::verifyExpiration)
        .map(RefreshToken::getUser)
        .map(user -> {
          String token = jwtUtils.generateTokenFromUsername(user.getUsername());
          return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
        })
        .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
            "Refresh token is not in database!"));
  }
  
  // Logout controller
  @PostMapping("/signout")
  public ResponseEntity<?> logoutUser() {
      Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

      if (principal instanceof UserDetailsImpl) {
          UserDetailsImpl userDetails = (UserDetailsImpl) principal;
          Long userId = userDetails.getId();
          refreshTokenService.deleteByUserId(userId);
          return ResponseEntity.ok(new MessageResponse("Log out successful!"));
      } else {
          return ResponseEntity.ok(new MessageResponse("Log out successful! (no user details)"));
      }
  }
  
  // Getting all users avaible in the database
  @GetMapping("/users")
  public ResponseEntity<?> getAllUsers() {
	    List<User> users = userRepository.findAll().stream()
	            .collect(Collectors.toList());

	    return ResponseEntity.ok(users);
  }
  
  // deleing a user by his id
  @DeleteMapping("/users/{userId}")
  public ResponseEntity<?> deleteUser(@PathVariable Long userId) {
      Optional<User> optionalUser = userRepository.findById(userId);
      if (optionalUser.isPresent()) {
          User user = optionalUser.get();
          refreshTokenService.deleteByUserId(userId);
          userRepository.delete(user);
          return ResponseEntity.ok(new MessageResponse("Utilisateur a été supprimé avec succés!"));
      } else {
          return ResponseEntity.badRequest().body(new MessageResponse("Erreur: Utlisateur non trouvé!"));
      }
  }
  
  // updating an existing user information
  @PutMapping("users/update/{id}")
  public ResponseEntity<?> updateUser(@PathVariable("id") Long id, @RequestBody SignupRequest signUpRequest) {
      Optional<User> optionalUser = userRepository.findById(id);

      if (!optionalUser.isPresent()) {
          return ResponseEntity.badRequest().body(new MessageResponse("Erreur: Utlisateur non trouvé!"));
      }

      User user = optionalUser.get();

      if (signUpRequest.getUsername() != null && !signUpRequest.getUsername().isEmpty()) {
          if (!user.getUsername().equals(signUpRequest.getUsername()) && userRepository.existsByUsername(signUpRequest.getUsername())) {
              return ResponseEntity.badRequest().body(new MessageResponse("Erreur: Nom d'utilisateur existe déjà!"));
          }

          user.setUsername(signUpRequest.getUsername());
      }

      if (signUpRequest.getEmail() != null && !signUpRequest.getEmail().isEmpty()) {
          if (!user.getEmail().equals(signUpRequest.getEmail()) && userRepository.existsByEmail(signUpRequest.getEmail())) {
              return ResponseEntity.badRequest().body(new MessageResponse("Erreur: Email existe déjà!"));
          }

          user.setEmail(signUpRequest.getEmail());
      }

      if (signUpRequest.getPassword() != null && !signUpRequest.getPassword().isEmpty()) {
          user.setPassword(encoder.encode(signUpRequest.getPassword()));
      }
      Set<String> strRoles = signUpRequest.getRole();
      Set<Role> roles = new HashSet<>();

      if (strRoles == null) {
          Role userRole = roleRepository.findByName(ERole.Client)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(userRole);
      } else {
          strRoles.forEach(role -> {
              switch (role) {
                  case "Admin":
                      Role adminRole = roleRepository.findByName(ERole.Admin)
                          .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                      roles.add(adminRole);
                      break;
                  case "Livreur":
                      Role modRole = roleRepository.findByName(ERole.Livreur)
                          .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                      roles.add(modRole);
                      break;
                  default:
                      Role userRole = roleRepository.findByName(ERole.Client)
                          .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                      roles.add(userRole);
              }
          });
      }

      user.setRoles(roles);

      userRepository.save(user);

      return ResponseEntity.ok(new MessageResponse("Utilisateur a été mis à jour avec succés!"));
  }
  
}


