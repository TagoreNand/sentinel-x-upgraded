ALTER TABLE `security_events`
  ADD COLUMN `sourceType` varchar(32) DEFAULT 'manual',
  ADD COLUMN `enrichment` json;
--> statement-breakpoint
ALTER TABLE `vulnerability_scans`
  ADD COLUMN `assetId` int,
  ADD COLUMN `executionMode` enum('evidence-driven','simulation') DEFAULT 'simulation',
  ADD COLUMN `disclaimer` text,
  ADD COLUMN `targetServices` json;
--> statement-breakpoint
ALTER TABLE `ids_rules`
  ADD COLUMN `dataSource` varchar(64) DEFAULT 'siem',
  ADD COLUMN `detectionLogic` json,
  ADD COLUMN `attackTactic` varchar(100),
  ADD COLUMN `thresholdCount` int DEFAULT 1,
  ADD COLUMN `thresholdWindowMinutes` int DEFAULT 5,
  ADD COLUMN `confidenceWeight` int DEFAULT 50;
--> statement-breakpoint
ALTER TABLE `ids_detections`
  ADD COLUMN `matchReasons` json,
  ADD COLUMN `mitreTechnique` varchar(100),
  ADD COLUMN `mitreTactic` varchar(100);
--> statement-breakpoint
ALTER TABLE `forensics_evidence`
  ADD COLUMN `classification` varchar(100),
  ADD COLUMN `storagePath` varchar(255);
--> statement-breakpoint
CREATE TABLE `assets` (
  `id` int AUTO_INCREMENT NOT NULL,
  `assetId` varchar(64) NOT NULL,
  `hostname` varchar(255) NOT NULL,
  `ipAddress` varchar(45),
  `assetType` varchar(100) DEFAULT 'server',
  `environment` varchar(64) DEFAULT 'production',
  `businessOwner` varchar(255),
  `operatingSystem` varchar(255),
  `criticality` enum('critical','high','medium','low') DEFAULT 'medium',
  `services` json,
  `tags` json,
  `metadata` json,
  `createdAt` timestamp NOT NULL DEFAULT (now()),
  `updatedAt` timestamp DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT `assets_id` PRIMARY KEY(`id`),
  CONSTRAINT `assets_assetId_unique` UNIQUE(`assetId`)
);
--> statement-breakpoint
CREATE INDEX `idx_asset_hostname` ON `assets` (`hostname`);
--> statement-breakpoint
CREATE INDEX `idx_asset_ip` ON `assets` (`ipAddress`);
--> statement-breakpoint
CREATE TABLE `forensics_custody_events` (
  `id` int AUTO_INCREMENT NOT NULL,
  `custodyEventId` varchar(64) NOT NULL,
  `evidenceId` int NOT NULL,
  `action` varchar(100) NOT NULL,
  `actorUserId` int,
  `notes` text,
  `hashSnapshot` json,
  `timestamp` timestamp NOT NULL DEFAULT (now()),
  CONSTRAINT `forensics_custody_events_id` PRIMARY KEY(`id`),
  CONSTRAINT `forensics_custody_events_custodyEventId_unique` UNIQUE(`custodyEventId`)
);
--> statement-breakpoint
CREATE TABLE `investigation_artifacts` (
  `id` int AUTO_INCREMENT NOT NULL,
  `artifactId` varchar(64) NOT NULL,
  `incidentId` int NOT NULL,
  `artifactType` varchar(100) NOT NULL,
  `title` varchar(255) NOT NULL,
  `sourceTable` varchar(100),
  `sourceRecordId` varchar(64),
  `tags` json,
  `metadata` json,
  `createdAt` timestamp NOT NULL DEFAULT (now()),
  CONSTRAINT `investigation_artifacts_id` PRIMARY KEY(`id`),
  CONSTRAINT `investigation_artifacts_artifactId_unique` UNIQUE(`artifactId`)
);
--> statement-breakpoint
CREATE TABLE `iam_events` (
  `id` int AUTO_INCREMENT NOT NULL,
  `iamEventId` varchar(64) NOT NULL,
  `provider` varchar(100) DEFAULT 'okta',
  `actor` varchar(255) NOT NULL,
  `action` varchar(255) NOT NULL,
  `target` varchar(255),
  `sourceIp` varchar(45),
  `status` varchar(50) DEFAULT 'observed',
  `anomalyScore` int DEFAULT 0,
  `metadata` json,
  `timestamp` timestamp NOT NULL DEFAULT (now()),
  `createdAt` timestamp NOT NULL DEFAULT (now()),
  CONSTRAINT `iam_events_id` PRIMARY KEY(`id`),
  CONSTRAINT `iam_events_iamEventId_unique` UNIQUE(`iamEventId`)
);
--> statement-breakpoint
CREATE TABLE `endpoint_telemetry` (
  `id` int AUTO_INCREMENT NOT NULL,
  `telemetryId` varchar(64) NOT NULL,
  `endpointId` varchar(100),
  `hostname` varchar(255) NOT NULL,
  `username` varchar(255),
  `processName` varchar(255),
  `parentProcess` varchar(255),
  `processHash` varchar(128),
  `commandLine` text,
  `destinationIp` varchar(45),
  `severity` enum('critical','high','medium','low') DEFAULT 'low',
  `status` varchar(50) DEFAULT 'observed',
  `tags` json,
  `metadata` json,
  `timestamp` timestamp NOT NULL DEFAULT (now()),
  `createdAt` timestamp NOT NULL DEFAULT (now()),
  CONSTRAINT `endpoint_telemetry_id` PRIMARY KEY(`id`),
  CONSTRAINT `endpoint_telemetry_telemetryId_unique` UNIQUE(`telemetryId`)
);
--> statement-breakpoint
CREATE TABLE `cloud_findings` (
  `id` int AUTO_INCREMENT NOT NULL,
  `findingId` varchar(64) NOT NULL,
  `provider` varchar(64) DEFAULT 'aws',
  `accountId` varchar(64),
  `resourceId` varchar(255) NOT NULL,
  `service` varchar(100),
  `findingType` varchar(255) NOT NULL,
  `severity` enum('critical','high','medium','low') DEFAULT 'medium',
  `status` varchar(50) DEFAULT 'open',
  `metadata` json,
  `timestamp` timestamp NOT NULL DEFAULT (now()),
  `createdAt` timestamp NOT NULL DEFAULT (now()),
  CONSTRAINT `cloud_findings_id` PRIMARY KEY(`id`),
  CONSTRAINT `cloud_findings_findingId_unique` UNIQUE(`findingId`)
);
--> statement-breakpoint
CREATE TABLE `phishing_analyses` (
  `id` int AUTO_INCREMENT NOT NULL,
  `analysisId` varchar(64) NOT NULL,
  `emailSubject` varchar(255) NOT NULL,
  `sender` varchar(320) NOT NULL,
  `recipient` varchar(320),
  `urlCount` int DEFAULT 0,
  `attachmentCount` int DEFAULT 0,
  `verdict` enum('malicious','suspicious','benign') DEFAULT 'suspicious',
  `confidence` int DEFAULT 50,
  `reasons` json,
  `indicators` json,
  `linkedIncidentId` int,
  `createdAt` timestamp NOT NULL DEFAULT (now()),
  CONSTRAINT `phishing_analyses_id` PRIMARY KEY(`id`),
  CONSTRAINT `phishing_analyses_analysisId_unique` UNIQUE(`analysisId`)
);
--> statement-breakpoint
CREATE TABLE `soar_playbooks` (
  `id` int AUTO_INCREMENT NOT NULL,
  `playbookId` varchar(64) NOT NULL,
  `name` varchar(255) NOT NULL,
  `description` text,
  `triggerType` varchar(100) NOT NULL,
  `enabled` boolean DEFAULT true,
  `steps` json NOT NULL,
  `createdBy` int,
  `createdAt` timestamp NOT NULL DEFAULT (now()),
  `updatedAt` timestamp DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT `soar_playbooks_id` PRIMARY KEY(`id`),
  CONSTRAINT `soar_playbooks_playbookId_unique` UNIQUE(`playbookId`)
);
--> statement-breakpoint
CREATE TABLE `soar_executions` (
  `id` int AUTO_INCREMENT NOT NULL,
  `executionId` varchar(64) NOT NULL,
  `playbookId` int NOT NULL,
  `incidentId` int,
  `triggerEntityType` varchar(100),
  `triggerEntityId` varchar(64),
  `status` varchar(50) DEFAULT 'pending',
  `output` json,
  `startedAt` timestamp NOT NULL DEFAULT (now()),
  `completedAt` timestamp,
  `createdAt` timestamp NOT NULL DEFAULT (now()),
  CONSTRAINT `soar_executions_id` PRIMARY KEY(`id`),
  CONSTRAINT `soar_executions_executionId_unique` UNIQUE(`executionId`)
);
--> statement-breakpoint
CREATE TABLE `platform_audit_logs` (
  `id` int AUTO_INCREMENT NOT NULL,
  `auditId` varchar(64) NOT NULL,
  `actorUserId` int,
  `action` varchar(255) NOT NULL,
  `entityType` varchar(100) NOT NULL,
  `entityId` varchar(100),
  `outcome` varchar(50) DEFAULT 'success',
  `details` json,
  `createdAt` timestamp NOT NULL DEFAULT (now()),
  CONSTRAINT `platform_audit_logs_id` PRIMARY KEY(`id`),
  CONSTRAINT `platform_audit_logs_auditId_unique` UNIQUE(`auditId`)
);
