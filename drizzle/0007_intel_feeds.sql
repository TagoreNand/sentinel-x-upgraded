-- External threat-intel feeds: TAXII 2.x collections, STIX bundle URLs, and
-- MISP restSearch endpoints. Polled into indicators_of_compromise so the
-- ingestion pipeline's IOC enrichment picks up external indicators. The
-- last-poll columns make a silently-failing feed observable.
CREATE TABLE `intel_feeds` (
  `id` int AUTO_INCREMENT NOT NULL,
  `feedId` varchar(64) NOT NULL,
  `name` varchar(255) NOT NULL,
  `type` enum('taxii','stix','misp') NOT NULL,
  `url` varchar(1024) NOT NULL,
  `authToken` varchar(1024),
  `defaultThreatLevel` enum('critical','high','medium','low') NOT NULL DEFAULT 'medium',
  `enabled` boolean NOT NULL DEFAULT true,
  `lastPolledAt` timestamp NULL,
  `lastStatus` varchar(32),
  `lastError` text,
  `lastIocCount` int DEFAULT 0,
  `createdBy` int,
  `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updatedAt` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT `intel_feeds_id` PRIMARY KEY(`id`),
  CONSTRAINT `intel_feeds_feedId_unique` UNIQUE(`feedId`)
);
--> statement-breakpoint
CREATE INDEX `idx_feed_enabled` ON `intel_feeds` (`enabled`);
