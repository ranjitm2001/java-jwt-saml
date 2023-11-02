package ai.osfin.jwtsaml.repository;

import lombok.Getter;
import lombok.Setter;

// The User class representing a user entity
@Getter
@Setter
public class MyUserDetail {
	private String username;
	private String password;

	public MyUserDetail(String username, String password) {
		this.username = username;
		this.password = password;
	}
}
