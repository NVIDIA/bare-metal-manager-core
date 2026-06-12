curl -X POST "https://api.example.com/v2/org/{tenant-org-name}/nico/sshkey" \
-H "Content-Type: application/json" -H "Accept: application/json" \
-H "Authorization: Bearer ${TOKEN}" \
-d '{
      "name": "customer-0",
      "description": "Demo public SSH key",
      "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAcV/3oxRllEji0wl9F6icRk+Kme0H2MMAPFizKB5yv8 demo-user@nvdia.com"
      }'
