ALTER TABLE nodes ADD COLUMN public_key VARCHAR(64) NULL;
CREATE TABLE node_enrollments (
 token_hash CHAR(64) PRIMARY KEY,
 node_id VARCHAR(36) NOT NULL,
 expires_at BIGINT NOT NULL,
 created_at BIGINT NOT NULL,
 FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE,
 UNIQUE KEY one_pending_enrollment(node_id),
 INDEX enrollment_expiry(expires_at)
) ENGINE=InnoDB;
CREATE TABLE node_nonces (
 node_id VARCHAR(36) NOT NULL,
 nonce VARCHAR(43) NOT NULL,
 expires_at BIGINT NOT NULL,
 PRIMARY KEY(node_id,nonce),
 FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE,
 INDEX nonce_expiry(expires_at)
) ENGINE=InnoDB;
