package ai.osfin.jwtsaml.repository;

import java.util.HashMap;
import java.util.Map;

import org.springframework.stereotype.Repository;

@Repository
// An example implementation of the UserRepository interface using an in-memory map
public class DummyUserRepository implements UserRepository {
	// Simulating an in-memory database
	private Map<String, MyUserDetail> userDatabase;

	public DummyUserRepository() {
		userDatabase = new HashMap<>();

		// Adding some dummy users for demonstration
		userDatabase.put("user1", new MyUserDetail("user1", "password1"));
		userDatabase.put("user2", new MyUserDetail("user2", "password2"));
		userDatabase.put("ranjitm2001@gmail.com", new MyUserDetail("ranjitm2001@gmail.com", "password2"));
	}

	@Override
	public MyUserDetail findByUsername(String username) {
		// Simulating the database query to find a user by username
		return userDatabase.get(username);
	}
}