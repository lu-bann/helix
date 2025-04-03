ALTER TABLE validator_preferences
ADD COLUMN "gossip_blobs" boolean DEFAULT false;

ALTER TABLE validator_preferences
ADD COLUMN "delay_ms" bigint DEFAULT 0;