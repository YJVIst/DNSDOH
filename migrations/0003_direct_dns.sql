ALTER TABLE nodes DROP INDEX endpoint;
ALTER TABLE nodes ADD COLUMN ip_address VARCHAR(45) NULL,
 ADD COLUMN deploy_state VARCHAR(32) NOT NULL DEFAULT 'legacy',
 ADD COLUMN domain_revision BIGINT NOT NULL DEFAULT 0,
 ADD COLUMN deleted_at BIGINT NULL;
CREATE TABLE dns_providers (
 id VARCHAR(36) PRIMARY KEY, kind VARCHAR(24) NOT NULL,
 name VARCHAR(100) NOT NULL, credential TEXT NOT NULL,
 created_at BIGINT NOT NULL
) ENGINE=InnoDB;
CREATE TABLE dns_domains (
 id VARCHAR(36) PRIMARY KEY, provider_id VARCHAR(36) NOT NULL,
 zone_id VARCHAR(253) NOT NULL, zone_name VARCHAR(253) NOT NULL,
 hostname VARCHAR(253) NOT NULL UNIQUE, controller_ip VARCHAR(45) NOT NULL,
 routing VARCHAR(32) NOT NULL DEFAULT 'multi_address',
 state VARCHAR(32) NOT NULL DEFAULT 'preparing',
 certificate MEDIUMTEXT NULL, cert_expires BIGINT NULL, cert_attempt_at BIGINT NOT NULL DEFAULT 0,
 revision BIGINT NOT NULL, last_error VARCHAR(500) NOT NULL DEFAULT '',
 checked_at BIGINT NULL, retire_at BIGINT NULL, controller_applied BIGINT NOT NULL DEFAULT 0, created_at BIGINT NOT NULL,
 FOREIGN KEY(provider_id) REFERENCES dns_providers(id)
) ENGINE=InnoDB;
CREATE TABLE dns_managed_records (
 id VARCHAR(36) PRIMARY KEY, domain_id VARCHAR(36) NOT NULL,
 node_id VARCHAR(36) NOT NULL, remote_id VARCHAR(255) NOT NULL,
 name VARCHAR(253) NOT NULL, record_type VARCHAR(8) NOT NULL,
 value VARCHAR(500) NOT NULL, purpose VARCHAR(24) NOT NULL,
 FOREIGN KEY(domain_id) REFERENCES dns_domains(id),
 UNIQUE KEY managed_remote(domain_id,remote_id)
) ENGINE=InnoDB;
CREATE TABLE infra_secrets (name VARCHAR(80) PRIMARY KEY, value MEDIUMTEXT NOT NULL) ENGINE=InnoDB;
CREATE TABLE infra_jobs (
 id VARCHAR(36) PRIMARY KEY, kind VARCHAR(32) NOT NULL, target VARCHAR(253) NOT NULL,
 state VARCHAR(32) NOT NULL, stage VARCHAR(500) NOT NULL,
 created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL
) ENGINE=InnoDB;
CREATE TABLE ssh_hosts (
 host VARCHAR(45) NOT NULL, port INT NOT NULL, fingerprint VARCHAR(100) NOT NULL,
 updated_at BIGINT NOT NULL, PRIMARY KEY(host,port)
) ENGINE=InnoDB;
