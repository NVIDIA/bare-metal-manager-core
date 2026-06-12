jq '[ .[] | {name: .name, ipAddresses: .instanceSubnets[].ipAddresses } ]'
