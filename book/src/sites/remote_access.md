# Remote Site Access Using an ssh Socks Proxy
ssh has the ability to create a socks proxy over an ssh connection.  Using a socks proxy over an ssh connection to a jump host gives several tools easy access to a site.

## Start the Proxy
```
ssh -fND 8888 <jumphost>
```
This start ssh and once authenticated drops into the background.
* -f run ssh in the background
* -N do not run a command on the jump host (its not allowed anyway)
* -D start the socks proxy on the specified local port

Note that port 8888 was chosen because it is what is in the SRE kubernetes configs

## logcli
```
$ export https_proxy='socks5://127.0.0.1:8888/'
$ logcli --addr="https://loki-dev3.frg.nvidia.com" --proxy-url="socks5://localhost:8888" --org-id="forge" query -o raw --since 1h  --limit 5 '{k8s_container_name="carbide-api"}'
2024/02/21 14:23:10 https://loki-dev3.frg.nvidia.com/loki/api/v1/query_range?direction=BACKWARD&end=1708543390912429573&limit=5&query=%7Bk8s_container_name%3D%22carbide-api%22%7D&start=1708539790912429573
2024/02/21 14:23:11 Common labels: {exporter="OTLP", k8s_container_name="carbide-api", k8s_namespace_name="forge-system", k8s_node_name="pdx01-m01-h16-cpu-1.fc.nvda.co", k8s_pod_name="carbide-api-68bfc6dd9c-mq6mh"}
level=SPAN span_id="0x6c99f1a6d198b20a" span_name=request status="Ok" busy_ns=3184586 client_address=::ffff:100.113.63.242 client_num_certs=2 client_port=40760 code_filepath=api/src/logging/api_logs.rs code_lineno=134 code_namespace=carbide::logging::api_logs elapsed_us=12588 forge_machine_id=fm100htm2m6m09mdurok5ckk27kc050achk6kfup8rhefrjlsnmlrm29560 http_response_status_code=200 http_url=https://carbide-api.forge-system.svc.cluster.local:1079/forge.Forge/GetBMCMetaData idle_ns=9553507 request="BmcMetaDataGetRequest { machine_id: Some(MachineId { id: \"fm100htm2m6m09mdurok5ckk27kc050achk6kfup8rhefrjlsnmlrm29560\" }), role: Administrator, request_type: Ipmi }" rpc_grpc_status_code=0 rpc_grpc_status_description="Code: The operation completed successfully, Message: " rpc_method=GetBMCMetaData rpc_service=forge.Forge service_name=carbide-api service_namespace=forge-system sql_max_query_duration_summary="SELECT machine_topologies.topology ->> \'bmc_info\' as bmc_info FROM machine_topologies WHERE machine_id = $1" sql_max_query_duration_us=0 sql_max_query_duration_us=766 sql_queries=0 sql_queries=2 sql_total_query_duration_us=0 sql_total_query_duration_us=1329 sql_total_rows_affected=0 sql_total_rows_affected=0 sql_total_rows_returned=0 sql_total_rows_returned=1 start_time=2024-02-21T19:23:08.332877946Z
level=ERROR span_id="0x9c8a6015916a9ecd" msg="Invalid build version" error="Build version should have at least a date" invalid_version=show-60-ge1e4035 location="api/src/model/machine/upgrade_policy.rs:44"
level=SPAN span_id="0x48e139c843579a98" span_name=state_controller_iteration status="Ok" busy_ns=6950057 code_filepath=api/src/state_controller/controller.rs code_lineno=113 code_namespace=carbide::state_controller::controller controller=network_segments_controller elapsed_us=15658 handler_latencies_us="{\"ready\":{\"min\":2254,\"max\":4603,\"avg\":3719}}" idle_ns=8680604 service_name=carbide-api service_namespace=forge-system skipped_iteration=false sql_max_query_duration_summary= sql_max_query_duration_us=0 sql_max_query_duration_us=1000 sql_queries=0 sql_queries=61 sql_total_query_duration_us=0 sql_total_query_duration_us=37816 sql_total_rows_affected=0 sql_total_rows_affected=57 sql_total_rows_returned=0 sql_total_rows_returned=58 start_time=2024-02-21T19:22:31.754575699Z states="{\"ready\":19}" states_above_sla={} times_in_state_s="{\"ready\":{\"min\":413721,\"max\":18320983,\"avg\":7652124}}"
level=ERROR span_id="0x75408014dd16ca6" msg="Invalid build version" error="Build version should have at least a date" invalid_version=show-60-ge1e4035 location="api/src/model/machine/upgrade_policy.rs:44"
level=ERROR span_id="0x2190dc7edbb7388f" msg="Invalid build version" error="Build version should have at least a date" invalid_version=show-60-ge1e4035 location="api/src/model/machine/upgrade_policy.rs:44"
```

## API Access with forge-admin-cli
Note that some sites allow direct access without a socks proxy.
```
$ export https_proxy='socks5://127.0.0.1:8888/'
$ forge-admin-cli -c https://api-dev3.frg.nvidia.com mh show fm100dsklnj215kqga6p25nlgbdhur5ag8qkmi7t35huebmraepk4oj4pag
Hostname    : louisiana-utah
State       : Ready

Host:
----------------------------------------
  ID                    : fm100htb5i9kvrghkdv9m60j1j6ujjh3lg2vdhl7aj8v2lkl54kc4519oug

[truncated]
```

## Redfish with forge-admin-cli
Redfish commands issued with forge-admin-cli go directly to the target IP and not to the carbide api.  Therefore they require the socks proxy if run locally.

```
$ export https_proxy='socks5://127.0.0.1:8888/'
$ forge-admin-cli -c https://api-dev3.frg.nvidia.com redfish get-power-state --address 10.217.133.20 --username root --password '********'
On

```

## Kubernetes
All kubernetes operations are available through the socks proxy if configured (no environment variables needed).

See [Configuring kubectl for site access](remote_kubernetes.md)

## Web Access
### Firefox
copy the following and put in a file
```
function FindProxyForURL(url, host) { 
    if (isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")) {
        //alert("url = " + url + " *** host = " + host + " *** Resolved IP = " + dnsResolve(host));
        return "SOCKS5 127.0.0.1:8888"; 
    }
    return "DIRECT";
}
```
use the file as the automatic proxy settings in firefox settings (general->network settings)
![](firefox-settings.png)
