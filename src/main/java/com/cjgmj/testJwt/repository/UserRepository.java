package com.cjgmj.testJwt.repository;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.cjgmj.testJwt.model.UserEntity;

@Repository
public interface UserRepository extends CrudRepository<UserEntity, Long> {

	public Optional<UserEntity> findByUsername(String username);

}
