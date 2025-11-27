package com.kartikeyajhamnani_017.LedgerEzBackend.repository;



import com.kartikeyajhamnani_017.LedgerEzBackend.model.Contact;
import com.kartikeyajhamnani_017.LedgerEzBackend.model.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ContactRepository extends JpaRepository<Contact, Integer> {

    /**
     * Checks if a contact relationship already exists between these two users.
     * This is the "Duplicate" check.
     */
    boolean existsByOwnerUserAndContactUser(UserEntity ownerUser, UserEntity contactUser);
}
