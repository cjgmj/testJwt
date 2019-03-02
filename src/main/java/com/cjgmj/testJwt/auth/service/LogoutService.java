package com.cjgmj.testJwt.auth.service;

public interface LogoutService {

	public void logout(String jwt);

	public boolean existsByUsername(String username);
	
	public void deleteByUsername(String username);

}
