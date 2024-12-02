-- Two tests in network_segment_update.rs need a second domain
-- Production sites only use one domain so far
INSERT INTO domains (id, name) VALUES ('48db2509-3b88-4db6-b77b-aa389d370e02', 'dwrt2.com');
