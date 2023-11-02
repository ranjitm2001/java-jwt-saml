package ai.osfin.jwtsaml.services;

import java.util.ArrayList;

import ai.osfin.jwtsaml.repository.UserRepository;
import ai.osfin.jwtsaml.repository.MyUserDetail;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	public MyUserDetailsService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// Fetch user details based on the provided username from the UserRepository
		MyUserDetail user = userRepository.findByUsername(username);
		if (user == null) {
			throw new UsernameNotFoundException("User not found with username: " + username);
		}

		// Convert the retrieved user details to a UserDetails object
		return new User(
			user.getUsername(), user.getPassword(), new ArrayList<>()
			// Add roles/authorities if applicable
		);
	}
}
