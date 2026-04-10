CREATE TABLE `alerts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`alertId` varchar(64) NOT NULL,
	`title` varchar(255) NOT NULL,
	`description` text,
	`severity` enum('critical','high','medium','low') NOT NULL,
	`ruleId` varchar(64),
	`ruleName` varchar(255),
	`sourceEvents` json,
	`status` varchar(50) DEFAULT 'new',
	`assignedTo` int,
	`incidentId` int,
	`metadata` json,
	`timestamp` timestamp DEFAULT (now()),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `alerts_id` PRIMARY KEY(`id`),
	CONSTRAINT `alerts_alertId_unique` UNIQUE(`alertId`)
);
--> statement-breakpoint
CREATE TABLE `cve_database` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cveId` varchar(20) NOT NULL,
	`title` varchar(255) NOT NULL,
	`description` text,
	`severity` enum('critical','high','medium','low') NOT NULL,
	`cvssScore` decimal(3,1),
	`affectedProducts` json,
	`publishedDate` timestamp,
	`updatedDate` timestamp,
	`references` json,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `cve_database_id` PRIMARY KEY(`id`),
	CONSTRAINT `cve_database_cveId_unique` UNIQUE(`cveId`)
);
--> statement-breakpoint
CREATE TABLE `forensics_evidence` (
	`id` int AUTO_INCREMENT NOT NULL,
	`evidenceId` varchar(64) NOT NULL,
	`incidentId` int,
	`filename` varchar(255) NOT NULL,
	`fileType` varchar(100),
	`fileSize` bigint,
	`md5Hash` varchar(32),
	`sha1Hash` varchar(40),
	`sha256Hash` varchar(64),
	`sha512Hash` varchar(128),
	`collectionMethod` varchar(255),
	`collectedBy` int,
	`collectedAt` timestamp,
	`chainOfCustody` json,
	`metadata` json,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `forensics_evidence_id` PRIMARY KEY(`id`),
	CONSTRAINT `forensics_evidence_evidenceId_unique` UNIQUE(`evidenceId`)
);
--> statement-breakpoint
CREATE TABLE `forensics_timeline` (
	`id` int AUTO_INCREMENT NOT NULL,
	`timelineId` varchar(64) NOT NULL,
	`incidentId` int NOT NULL,
	`eventDescription` varchar(255) NOT NULL,
	`eventTimestamp` timestamp,
	`source` varchar(100),
	`severity` enum('critical','high','medium','low') DEFAULT 'low',
	`details` json,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `forensics_timeline_id` PRIMARY KEY(`id`),
	CONSTRAINT `forensics_timeline_timelineId_unique` UNIQUE(`timelineId`)
);
--> statement-breakpoint
CREATE TABLE `honeypot_interactions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`interactionId` varchar(64) NOT NULL,
	`honeypotId` int NOT NULL,
	`attackerIp` varchar(45) NOT NULL,
	`attackerPort` int,
	`attackerCountry` varchar(100),
	`attackerCity` varchar(100),
	`attackerLatitude` decimal(10,6),
	`attackerLongitude` decimal(10,6),
	`interactionType` varchar(100),
	`payload` text,
	`credentials` json,
	`userAgent` text,
	`timestamp` timestamp DEFAULT (now()),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `honeypot_interactions_id` PRIMARY KEY(`id`),
	CONSTRAINT `honeypot_interactions_interactionId_unique` UNIQUE(`interactionId`)
);
--> statement-breakpoint
CREATE TABLE `honeypots` (
	`id` int AUTO_INCREMENT NOT NULL,
	`honeypotId` varchar(64) NOT NULL,
	`name` varchar(255) NOT NULL,
	`description` text,
	`serviceType` varchar(100) NOT NULL,
	`bindPort` int NOT NULL,
	`bindIp` varchar(45),
	`enabled` boolean DEFAULT true,
	`interactionCount` int DEFAULT 0,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `honeypots_id` PRIMARY KEY(`id`),
	CONSTRAINT `honeypots_honeypotId_unique` UNIQUE(`honeypotId`)
);
--> statement-breakpoint
CREATE TABLE `ids_detections` (
	`id` int AUTO_INCREMENT NOT NULL,
	`detectionId` varchar(64) NOT NULL,
	`ruleId` int NOT NULL,
	`eventId` int,
	`sourceIp` varchar(45),
	`destinationIp` varchar(45),
	`incidentId` int,
	`confidence` int DEFAULT 50,
	`timestamp` timestamp DEFAULT (now()),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `ids_detections_id` PRIMARY KEY(`id`),
	CONSTRAINT `ids_detections_detectionId_unique` UNIQUE(`detectionId`)
);
--> statement-breakpoint
CREATE TABLE `ids_rules` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ruleId` varchar(64) NOT NULL,
	`ruleName` varchar(255) NOT NULL,
	`description` text,
	`ruleType` varchar(100),
	`pattern` text,
	`severity` enum('critical','high','medium','low') DEFAULT 'medium',
	`enabled` boolean DEFAULT true,
	`attackTechnique` varchar(100),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `ids_rules_id` PRIMARY KEY(`id`),
	CONSTRAINT `ids_rules_ruleId_unique` UNIQUE(`ruleId`)
);
--> statement-breakpoint
CREATE TABLE `incident_audit_trail` (
	`id` int AUTO_INCREMENT NOT NULL,
	`incidentId` int NOT NULL,
	`action` varchar(100) NOT NULL,
	`performedBy` int,
	`details` json,
	`timestamp` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `incident_audit_trail_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `incident_playbooks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`incidentId` int NOT NULL,
	`stepNumber` int NOT NULL,
	`title` varchar(255) NOT NULL,
	`description` text,
	`status` varchar(50) DEFAULT 'pending',
	`assignedTo` int,
	`completedAt` timestamp,
	`notes` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `incident_playbooks_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `incidents` (
	`id` int AUTO_INCREMENT NOT NULL,
	`incidentId` varchar(64) NOT NULL,
	`title` varchar(255) NOT NULL,
	`description` text,
	`severity` enum('critical','high','medium','low') NOT NULL,
	`status` enum('open','investigating','contained','resolved') DEFAULT 'open',
	`classification` varchar(100),
	`assignedTo` int,
	`createdBy` int,
	`detectedAt` timestamp,
	`containedAt` timestamp,
	`resolvedAt` timestamp,
	`affectedAssets` json,
	`rootCause` text,
	`timeline` json,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `incidents_id` PRIMARY KEY(`id`),
	CONSTRAINT `incidents_incidentId_unique` UNIQUE(`incidentId`)
);
--> statement-breakpoint
CREATE TABLE `indicators_of_compromise` (
	`id` int AUTO_INCREMENT NOT NULL,
	`iocId` varchar(64) NOT NULL,
	`iocType` enum('ip','domain','url','hash','email','file','process','registry') NOT NULL,
	`iocValue` varchar(512) NOT NULL,
	`threatLevel` enum('critical','high','medium','low') DEFAULT 'medium',
	`source` varchar(255),
	`threatActorId` int,
	`firstSeen` timestamp,
	`lastSeen` timestamp,
	`confidence` int DEFAULT 50,
	`status` varchar(50) DEFAULT 'active',
	`metadata` json,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `indicators_of_compromise_id` PRIMARY KEY(`id`),
	CONSTRAINT `indicators_of_compromise_iocId_unique` UNIQUE(`iocId`)
);
--> statement-breakpoint
CREATE TABLE `security_events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`eventId` varchar(64) NOT NULL,
	`sourceIp` varchar(45),
	`destinationIp` varchar(45),
	`sourcePort` int,
	`destinationPort` int,
	`protocol` varchar(20),
	`eventType` varchar(100) NOT NULL,
	`eventCategory` varchar(100),
	`rawLog` text,
	`parsedData` json,
	`severity` enum('critical','high','medium','low') DEFAULT 'low',
	`status` varchar(50) DEFAULT 'new',
	`correlationId` varchar(64),
	`userId` int,
	`hostname` varchar(255),
	`username` varchar(255),
	`timestamp` timestamp DEFAULT (now()),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `security_events_id` PRIMARY KEY(`id`),
	CONSTRAINT `security_events_eventId_unique` UNIQUE(`eventId`)
);
--> statement-breakpoint
CREATE TABLE `threat_actors` (
	`id` int AUTO_INCREMENT NOT NULL,
	`actorId` varchar(64) NOT NULL,
	`name` varchar(255) NOT NULL,
	`aliases` json,
	`description` text,
	`sophistication` enum('novice','intermediate','advanced','expert') DEFAULT 'intermediate',
	`motivations` json,
	`targetedIndustries` json,
	`attackTechniques` json,
	`knownIncidents` int DEFAULT 0,
	`firstSeen` timestamp,
	`lastSeen` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `threat_actors_id` PRIMARY KEY(`id`),
	CONSTRAINT `threat_actors_actorId_unique` UNIQUE(`actorId`)
);
--> statement-breakpoint
CREATE TABLE `vulnerabilities` (
	`id` int AUTO_INCREMENT NOT NULL,
	`vulnerabilityId` varchar(64) NOT NULL,
	`scanId` int NOT NULL,
	`cveId` varchar(20),
	`title` varchar(255) NOT NULL,
	`description` text,
	`severity` enum('critical','high','medium','low') NOT NULL,
	`affectedService` varchar(255),
	`affectedPort` int,
	`remediationSteps` text,
	`status` varchar(50) DEFAULT 'open',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `vulnerabilities_id` PRIMARY KEY(`id`),
	CONSTRAINT `vulnerabilities_vulnerabilityId_unique` UNIQUE(`vulnerabilityId`)
);
--> statement-breakpoint
CREATE TABLE `vulnerability_scans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scanId` varchar(64) NOT NULL,
	`targetHost` varchar(255) NOT NULL,
	`targetIp` varchar(45),
	`scanType` varchar(100),
	`status` varchar(50) DEFAULT 'pending',
	`startTime` timestamp,
	`endTime` timestamp,
	`vulnerabilitiesFound` int DEFAULT 0,
	`criticalCount` int DEFAULT 0,
	`highCount` int DEFAULT 0,
	`mediumCount` int DEFAULT 0,
	`lowCount` int DEFAULT 0,
	`riskScore` decimal(5,2) DEFAULT '0.00',
	`results` json,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `vulnerability_scans_id` PRIMARY KEY(`id`),
	CONSTRAINT `vulnerability_scans_scanId_unique` UNIQUE(`scanId`)
);
--> statement-breakpoint
CREATE INDEX `idx_alert_severity` ON `alerts` (`severity`);--> statement-breakpoint
CREATE INDEX `idx_alert_status` ON `alerts` (`status`);--> statement-breakpoint
CREATE INDEX `idx_alert_timestamp` ON `alerts` (`timestamp`);--> statement-breakpoint
CREATE INDEX `idx_cve_id` ON `cve_database` (`cveId`);--> statement-breakpoint
CREATE INDEX `idx_cve_severity` ON `cve_database` (`severity`);--> statement-breakpoint
CREATE INDEX `idx_attacker_ip` ON `honeypot_interactions` (`attackerIp`);--> statement-breakpoint
CREATE INDEX `idx_honeypot_id` ON `honeypot_interactions` (`honeypotId`);--> statement-breakpoint
CREATE INDEX `idx_detection_rule` ON `ids_detections` (`ruleId`);--> statement-breakpoint
CREATE INDEX `idx_detection_source` ON `ids_detections` (`sourceIp`);--> statement-breakpoint
CREATE INDEX `idx_incident_status` ON `incidents` (`status`);--> statement-breakpoint
CREATE INDEX `idx_incident_severity` ON `incidents` (`severity`);--> statement-breakpoint
CREATE INDEX `idx_ioc_value` ON `indicators_of_compromise` (`iocValue`);--> statement-breakpoint
CREATE INDEX `idx_ioc_type` ON `indicators_of_compromise` (`iocType`);--> statement-breakpoint
CREATE INDEX `idx_source_ip` ON `security_events` (`sourceIp`);--> statement-breakpoint
CREATE INDEX `idx_severity` ON `security_events` (`severity`);--> statement-breakpoint
CREATE INDEX `idx_timestamp` ON `security_events` (`timestamp`);