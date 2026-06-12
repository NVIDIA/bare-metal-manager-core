curl -X POST "https://api.example.com/v2/org/{tenant-org-name}/nico/sshkeygroup" \
-H "Content-Type: application/json" -H "Accept: application/json" \
-H "Authorization: Bearer ${TOKEN}" \
-d '{
      "name": "demo-team-0-group",
      "description": "Demo team group"
   }'
