package com.cjgmj.testJwt.auth.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.cjgmj.testJwt.auth.service.LogoutService;
import com.cjgmj.testJwt.model.LogoutEntity;
import com.cjgmj.testJwt.repository.LogoutRepository;

@Service
public class LogoutServiceImpl implements LogoutService {

	@Autowired
	private LogoutRepository logoutRepository;

	@Override
	public void logout(String jwt) {
		LogoutEntity entity = new LogoutEntity();
		entity.setUsername(SecurityContextHolder.getContext().getAuthentication().getName());
		logoutRepository.save(entity);
	}

	@Override
	public boolean existsByUsername(String jwt) {
		return logoutRepository.existsByUsername(jwt);
	}

	@Transactional(readOnly = false)
	@Override
	public void deleteByUsername(String username) {
		logoutRepository.deleteByUsername(username);
	}

}
