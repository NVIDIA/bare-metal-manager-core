-- Add a field to store the health report sent by the log parser
ALTER TABLE machines ADD COLUMN log_parser_health_report jsonb;
