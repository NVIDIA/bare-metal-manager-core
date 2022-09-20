ALTER TABLE machine_console_metadata ADD FOREIGN KEY(machine_id) REFERENCES machines(id);
