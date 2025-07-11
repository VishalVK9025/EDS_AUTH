package com.eds.auth.repositories;

import com.eds.auth.entities.User;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<User, String> {
    Optional<User> findByUsername(String username);

    Optional<User> findUserByUsernameAndOriginalPassword(String username, String password);
}
