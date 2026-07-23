-- Notification channels + delivery ledger.
-- Channels are runtime-managed targets (Slack / generic webhook / email);
-- deliveries are the observable audit trail of every send attempt, so a
-- missed page can be diagnosed after the fact.
CREATE TABLE `notification_channels` (
  `id` int AUTO_INCREMENT NOT NULL,
  `channelId` varchar(64) NOT NULL,
  `name` varchar(255) NOT NULL,
  `type` enum('slack','webhook','email') NOT NULL,
  `target` varchar(1024) NOT NULL,
  `minSeverity` enum('critical','high','medium','low') NOT NULL DEFAULT 'high',
  `enabled` boolean NOT NULL DEFAULT true,
  `createdBy` int,
  `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updatedAt` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT `notification_channels_id` PRIMARY KEY(`id`),
  CONSTRAINT `notification_channels_channelId_unique` UNIQUE(`channelId`)
);
--> statement-breakpoint
CREATE INDEX `idx_channel_enabled` ON `notification_channels` (`enabled`);
--> statement-breakpoint
CREATE TABLE `notification_deliveries` (
  `id` int AUTO_INCREMENT NOT NULL,
  `deliveryId` varchar(64) NOT NULL,
  `channelId` int NOT NULL,
  `incidentId` int,
  `status` enum('sent','failed','skipped') NOT NULL,
  `statusCode` int,
  `error` text,
  `attempts` int NOT NULL DEFAULT 0,
  `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT `notification_deliveries_id` PRIMARY KEY(`id`),
  CONSTRAINT `notification_deliveries_deliveryId_unique` UNIQUE(`deliveryId`)
);
--> statement-breakpoint
CREATE INDEX `idx_delivery_incident` ON `notification_deliveries` (`incidentId`);
--> statement-breakpoint
CREATE INDEX `idx_delivery_channel` ON `notification_deliveries` (`channelId`);
