-- Expand RBAC: the flat user/admin model becomes a
-- viewer < analyst < lead < admin hierarchy.
--
-- A direct narrowing ALTER would coerce every existing 'user' row to '' (the
-- empty-string fallback MySQL uses for out-of-range enum values) — silent
-- data corruption of the authorization column. So this is done in three
-- phases: widen to a superset, remap the legacy value, then narrow.

-- Phase 1: widen to a superset enum so both the old and new values are valid.
ALTER TABLE `users`
  MODIFY COLUMN `role` ENUM('user','viewer','analyst','lead','admin') NOT NULL DEFAULT 'viewer';
--> statement-breakpoint
-- Phase 2: remap legacy 'user' accounts to 'analyst'. Under the old model
-- every authenticated user had full access; 'analyst' preserves day-to-day
-- investigation while removing IDS rule-authoring and SOAR execution, which
-- are now lead-gated. Admins are unaffected.
UPDATE `users` SET `role` = 'analyst' WHERE `role` = 'user';
--> statement-breakpoint
-- Phase 3: narrow to the final hierarchy. No 'user' rows remain, so the
-- narrowing is lossless.
ALTER TABLE `users`
  MODIFY COLUMN `role` ENUM('viewer','analyst','lead','admin') NOT NULL DEFAULT 'viewer';
