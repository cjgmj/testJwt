package com.cjgmj.testJwt.repository;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.cjgmj.testJwt.model.LogoutEntity;

@Repository
public interface LogoutRepository extends CrudRepository<LogoutEntity, Long> {

	public boolean existsByUsername(String username);
	
	@Modifying
	public void deleteByUsername(String username);

}
