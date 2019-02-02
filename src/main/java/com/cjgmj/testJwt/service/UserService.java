package com.cjgmj.testJwt.service;

import java.util.Optional;

import com.cjgmj.testJwt.model.UserEntity;

public interface UserService {
	public Optional<UserEntity> findByUsername(String username);
}
