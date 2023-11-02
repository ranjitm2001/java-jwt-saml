package ai.osfin.jwtsaml.repository;

public interface UserRepository {
	MyUserDetail findByUsername(String username);
}
