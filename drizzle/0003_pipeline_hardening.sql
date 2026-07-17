-- Pipeline hardening: incident idempotency + indexed threshold queries.
--
-- correlationKey is the atomic dedup guarantee for pipeline-created
-- incidents: concurrent ingest workers computing the same (rule, entity,
-- time-bucket) key race on this UNIQUE index and exactly one insert wins.
-- Nullable on purpose — analyst-created incidents have no correlation key,
-- and MySQL unique indexes permit multiple NULLs.
ALTER TABLE `incidents`
  ADD COLUMN `correlationKey` varchar(64);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_incident_correlation` ON `incidents` (`correlationKey`);
--> statement-breakpoint
-- Composite indexes so threshold rules ("N failures from one IP in M
-- minutes") resolve as an index range scan instead of a table scan.
CREATE INDEX `idx_source_ip_ts` ON `security_events` (`sourceIp`, `timestamp`);
--> statement-breakpoint
CREATE INDEX `idx_username_ts` ON `security_events` (`username`, `timestamp`);
