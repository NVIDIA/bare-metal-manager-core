# Configuring kubectl for site access
The instructions below show how to configure kubectl for remote access through a jump host for accessing site kubernetes.


### Assumptions
1. ssh access to the site through a jump host has already been configured.
2. Examples below use dev3, but any site can be used.
3. the jump host has a socks proxy running on port 8080

## Context Setup
1. Get the config from the site control node.
	1. ssh to the control node
	2. copy the config from /etc/kubernetes/admin.conf to your local working directory (I just copy and paste)
2. edit temp file.  in the `- cluster` section
	1. change "server" from localhost to actual control node ip.
	2. add `proxy-url: socks5://localhost:8080`  (same level as `server`)
	3. change name from kubernetes (which may conflict with other configs)
	4. change `cluster` in `- context` to match the cluster name (from previous step)
	5. change the user to something unique:  
		1. rename `kubernetes-admin` to `dev3-admin`
		2. make sure you rename all the references as well.
	3. you may wish to update the name of the context as well
3. copy `~/.kube/config` to your working directory
	1. `cp ~/.kube/config local.conf`
3. merge the config into your kube config:
	1. `KUBECONFIG=./dev3.conf:./local.conf kubectl config view --merge --flatten > all-kube.config`
2. Verify that the output config is has all the clusters with unique names.
3. Copy the new config back to ~/.kube/config
4. Port forward 8080 to the jumphost
	1. `ssh -ND 8080 renojump`
	2. this is the same local port as used in the socks proxy config.  any port can be used as long as they match

## Example Usage
```
$kubectl config get-contexts
CURRENT   NAME       CLUSTER            AUTHINFO      NAMESPACE
          demo1      demo1              demo1-admin   
*         dev3       dev3               dev3-admin    
          microk8s   microk8s-cluster   admin      
             
$kubectl config use-context demo1
Switched to context "demo1".

$kubectl get pods
NAME                                                READY   STATUS    RESTARTS   AGE
demo1-nvssh-nvssh-enabler-nkr58                     1/1     Running   0          21d
external-secrets-8556c9d457-ttlbt                   1/1     Running   0          21d
external-secrets-cert-controller-645df6dddc-z6dkr   1/1     Running   0          21d
external-secrets-webhook-6cb4dbd548-mx9rp           1/1     Running   0          21d
nettools-pod                                        1/1     Running   0          8d

$kubectl config use-context dev3
Switched to context "dev3".

$kubectl get pods
NAME                                                READY   STATUS    RESTARTS   AGE
external-secrets-697c97885c-6g9wr                   1/1     Running   0          58d
external-secrets-cert-controller-7cc8f54b75-8zx2l   1/1     Running   0          58d
external-secrets-webhook-795f994c48-w5x44           1/1     Running   0          58d
nettools-pod                                        1/1     Running   0          50d

```
