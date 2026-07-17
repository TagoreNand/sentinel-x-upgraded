-- Asynchronous ingestion: durable job ledger backing the queue.
-- The queue transport (Redis/BullMQ or in-process fallback) only delivers;
-- this table owns state. Status transitions are claimed atomically via
-- UPDATE ... WHERE status='queued', so duplicate deliveries cannot
-- double-process a job.
CREATE TABLE `ingest_jobs` (
  `id` int AUTO_INCREMENT NOT NULL,
  `ingestId` varchar(64) NOT NULL,
  `sourceType` varchar(32) NOT NULL,
  `payload` json,
  `assetId` int,
  `requestedBy` int,
  `status` enum('queued','processing','completed','failed') NOT NULL DEFAULT 'queued',
  `attempts` int NOT NULL DEFAULT 0,
  `result` json,
  `error` text,
  `queuedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `startedAt` timestamp NULL,
  `completedAt` timestamp NULL,
  CONSTRAINT `ingest_jobs_id` PRIMARY KEY(`id`),
  CONSTRAINT `ingest_jobs_ingestId_unique` UNIQUE(`ingestId`)
);
--> statement-breakpoint
CREATE INDEX `idx_ingest_status_queued` ON `ingest_jobs` (`status`, `queuedAt`);
--> statement-breakpoint
CREATE INDEX `idx_ingest_status_started` ON `ingest_jobs` (`status`, `startedAt`);
