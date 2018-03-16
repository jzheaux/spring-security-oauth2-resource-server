package org.springframework.security.samples.oauth2.rs.auth0;

import org.springframework.data.repository.CrudRepository;
import org.springframework.security.access.prepost.PreAuthorize;

import java.util.Optional;

/**
 * @author Rob Winch
 */
public interface MessageRepository extends CrudRepository<Message,Long> {
    @PreAuthorize("authentication.hasClaim('scope').thatMatches('.*message.read.*')")
    Optional<Message> findById(Long id);

    @PreAuthorize("hasAuthority('message.write')")
    Message save(Message message);
}
