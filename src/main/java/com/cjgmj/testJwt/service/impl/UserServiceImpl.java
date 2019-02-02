package com.cjgmj.testJwt.service.impl;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.cjgmj.testJwt.model.UserEntity;
import com.cjgmj.testJwt.repository.UserRepository;
import com.cjgmj.testJwt.service.UserService;

@Service
public class UserServiceImpl implements UserService {
	
	@Autowired
	private UserRepository userRepository;
	
	@Override
	public Optional<UserEntity> findByUsername(String username) {
		return userRepository.findByUsername(username);
	}

}
