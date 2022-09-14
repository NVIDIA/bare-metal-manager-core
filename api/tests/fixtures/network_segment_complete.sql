INSERT INTO domains (id, name) VALUES ('7687f939-727c-431e-a474-e15d70a9a728', 'test1.domain.com');
INSERT INTO vpcs (id, name, organization_id) VALUES ('885906cf-cfd0-477f-91e1-38b9a65c8c28', 'vpc1', '355afc3e-6c19-4b56-a53b-ef058c56e3dc');
INSERT INTO network_segments (id, name, subdomain_id, vpc_id, mtu) VALUES ('c11169d9-ad20-4705-8707-4e62a3ad4731', 'segment1', '7687f939-727c-431e-a474-e15d70a9a728', '885906cf-cfd0-477f-91e1-38b9a65c8c28', 1500);

INSERT INTO domains (id, name) VALUES ('04d015b9-56e9-4e1b-84f0-5574893cd576', 'test2.domain.com');
INSERT INTO vpcs (id, name, organization_id) VALUES ('6ff68e7a-c54e-42a0-8ae2-8e63180c97af', 'vpc2', '355afc3e-6c19-4b56-a53b-ef058c56e3dc');
