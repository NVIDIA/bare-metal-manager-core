-- Add migration script here

CREATE TABLE machine_state_controller_lock(
	id uuid DEFAULT gen_random_uuid() NOT NULL
);
