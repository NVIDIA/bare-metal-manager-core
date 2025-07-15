import requests
import sys
import time
import json
from datetime import datetime
from typing import Literal

class DellFactoryResetMethods:
    def __init__(self, host_bmc_ip, host_bmc_username, host_bmc_password):
        self.host_bmc_ip = host_bmc_ip
        self.host_bmc_username = host_bmc_username
        self.host_bmc_password = host_bmc_password

    def reset_bios(self):
        url = "https://%s/redfish/v1/Systems/System.Embedded.1/Bios/Actions/Bios.ResetBios" % self.host_bmc_ip
        payload = {}
        headers = {'content-type': 'application/json'}
        response = requests.post(
            url, json=payload, headers=headers,
            verify=False, auth=(
                self.host_bmc_username, self.host_bmc_password))
        if response.status_code == 200:
            print("\n- PASS: status code %s returned for POST command to reset BIOS to default settings" % response.status_code)
        else:
            print("\n- FAIL, Command failed, status code is %s" % response.status_code)
            detail_message = str(response.__dict__)
            if "reset the iDRAC" in detail_message:
                print("WARNING: Failed to reset the BIOS. Continuing with factory-reset...")
            else:
                print(detail_message)
                sys.exit(1)

    def get_server_status(self):
        for _ in range(10):
            try:
                response = requests.get(
                    'https://%s/redfish/v1/Systems/System.Embedded.1' % self.host_bmc_ip,
                    verify=False, auth=(self.host_bmc_username, self.host_bmc_password))
                data = response.json()
                break
            except json.decoder.JSONDecodeError:
                print("Error: Failed to decode JSON response from Redfish API. Retrying in 5 seconds...")
                time.sleep(5)
        return data

    def reboot_server(self):
        data = self.get_server_status()
        print("\n- INFO, Current server power state is: %s" % data['PowerState'])
        if data['PowerState'] == "On":
            url = 'https://%s/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset' % self.host_bmc_ip
            payload = {'ResetType': 'GracefulShutdown'}
            headers = {'content-type': 'application/json'}
            response = requests.post(
                url, json=payload, headers=headers,
                verify=False, auth=(self.host_bmc_username, self.host_bmc_password))
            if response.status_code == 204:
                print("- PASS, POST command passed to gracefully power OFF server, status code return is %s" % response.status_code)
                print("- INFO, script will now verify the server was able to perform a graceful shutdown. If the server was unable to perform a graceful shutdown, forced shutdown will be invoked in 5 minutes")
                time.sleep(15)
                start_time = datetime.now()
            else:
                print("\n- FAIL, Command failed to gracefully power OFF server, status code is: %s\n" % response.status_code)
                print("Extended Info Message: {0}".format(response.json()))
                sys.exit(1)
            while True:
                response = requests.get(
                    'https://%s/redfish/v1/Systems/System.Embedded.1' % self.host_bmc_ip,
                    verify=False, auth=(self.host_bmc_username, self.host_bmc_password))
                data = response.json()
                current_time = str(datetime.now() - start_time)[0:7]
                if data['PowerState'] == "Off":
                    print("- PASS, GET command passed to verify graceful shutdown was successful and server is in OFF state")
                    break
                elif current_time >= "0:05:00":
                    print("- INFO, unable to perform graceful shutdown, server will now perform forced shutdown")
                    payload = {'ResetType': 'ForceOff'}
                    headers = {'content-type': 'application/json'}
                    response = requests.post(
                        url, json=payload, headers=headers, verify=False,
                        auth=(self.host_bmc_username, self.host_bmc_password))
                    if response.status_code == 204:
                        print("- PASS, POST command passed to perform forced shutdown, status code return is %s" % response.status_code)
                        time.sleep(15)
                        response = requests.get(
                            'https://%s/redfish/v1/Systems/System.Embedded.1' % self.host_bmc_ip,
                            verify=False, auth=(self.host_bmc_username, self.host_bmc_password))
                        data = response.json()
                        if data['PowerState'] == "Off":
                            print("- PASS, GET command passed to verify forced shutdown was successful and server is in OFF state")
                            break
                        else:
                            print("- FAIL, server not in OFF state, current power status is %s" % data['PowerState'])
                            sys.exit(1)
                else:
                    continue
            payload = {'ResetType': 'On'}
            headers = {'content-type': 'application/json'}
            response = requests.post(
                url, json=payload, headers=headers,
                verify=False, auth=(self.host_bmc_username, self.host_bmc_password))
            if response.status_code == 204:
                print("- PASS, Command passed to power ON server, status code return is %s" % response.status_code)
            else:
                print("\n- FAIL, Command failed to power ON server, status code is: %s\n" % response.status_code)
                print("Extended Info Message: {0}".format(response.json()))
                sys.exit(1)
        elif data['PowerState'] == "Off":
            url = 'https://%s/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset' % self.host_bmc_ip
            payload = {'ResetType': 'On'}
            headers = {'content-type': 'application/json'}
            response = requests.post(
                url, json=payload, headers=headers, verify=False,
                auth=(self.host_bmc_username, self.host_bmc_password))
            if response.status_code == 204:
                print("- PASS, Command passed to power ON server, code return is %s" % response.status_code)
            else:
                print("\n- FAIL, Command failed to power ON server, status code is: %s\n" % response.status_code)
                print("Extended Info Message: {0}".format(response.json()))
                sys.exit(1)
        else:
            print("- FAIL, unable to get current server power state to perform either reboot or power on")
            sys.exit(1)

    def unlock_idrac(self):
        print("Unlocking iDRAC")
        url = f"https://{self.host_bmc_ip}/redfish/v1/Managers/iDRAC.Embedded.1/Attributes"
        payload = {"Attributes": {"Lockdown.1.SystemLockdown": "Disabled"}}
        headers = {'Content-Type': 'application/json'}
        try:
            response = requests.patch(url, headers=headers, json=payload, auth=(self.host_bmc_username, self.host_bmc_password), verify=False)
            if response.status_code != 200:
                print(f"Unlocking iDRAC failed. Status code: {response.status_code}")
                print(response.text)
        except Exception as e:
            print(f"Error unlocking iDRAC: {e}")
            sys.exit(1)

    def disable_host_header_check(self):
        print("Disabling host header check")
        url = f"https://{self.host_bmc_ip}/redfish/v1/Managers/iDRAC.Embedded.1/Attributes"
        payload = {"Attributes": {"WebServer.1.HostHeaderCheck": "Disabled"}}
        headers = {'Content-Type': 'application/json'}
        response = requests.patch(url, headers=headers, json=payload, auth=(self.host_bmc_username, self.host_bmc_password), verify=False)
        if response.status_code != 200:
            print(f"Disabling host header check failed. Status code: {response.status_code}")
            print(response.text)
            sys.exit(1)
        print("Disabling host header check successful.")

    def factory_reset_bmc(self, level: Literal["Default", "ResetAllWithRootDefaults", "All"] = "Default"):
        url = f"https://{self.host_bmc_ip}/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Oem/DellManager.ResetToDefaults"
        payload = {"ResetType": level}
        headers = {'content-type': 'application/json'}
        response = requests.post(
            url, json=payload, headers=headers,
            verify=False, auth=(self.host_bmc_username, self.host_bmc_password))
        if response.status_code == 200:
            print("\n- PASS, status code %s returned for POST command to reset iDRAC to \"%s\" setting\n" % (response.status_code, level))
        else:
            data = response.json()
            print("\n- FAIL, status code %s returned, error is: \n%s" % (response.status_code, data))
            sys.exit(1)
        time.sleep(15)
        print("- INFO, iDRAC will now reset and be back online within a few minutes.")

    def change_bmc_password(self, password: str):
        print("Changing iDRAC root password")
        url = f"https://{self.host_bmc_ip}/redfish/v1/Managers/iDRAC.Embedded.1/Accounts/2"
        payload = {"Password": password}
        headers = {'Content-Type': 'application/json'}
        try:
            response = requests.patch(
                url,
                headers=headers,
                json=payload,
                auth=(self.host_bmc_username, self.host_bmc_password),
                verify=False
            )
            if response.status_code == 200:
                print("- PASS, iDRAC root password changed successfully")
                return True
            else:
                print(f"- FAIL, Failed to change password. Status code: {response.status_code}")
                print(response.text)
                return False
        except Exception as e:
            print(f"- ERROR, Exception occurred while changing password: {e}")
            return False
        