package com.kartikeyajhamnani_017.LedgerEzBackend.repository;

import com.kartikeyajhamnani_017.LedgerEzBackend.model.UserEntity;
import com.kartikeyajhamnani_017.LedgerEzBackend.model.WalletEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface WalletRepository extends JpaRepository<WalletEntity, Integer> {

    /**
     * We will frequently need to find a wallet based on the authenticated user.
     * This method provides a clean way to do that.
     */
    Optional<WalletEntity> findByUser(UserEntity user);
}