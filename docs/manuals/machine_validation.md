Host Validation
===============


# Getting Started

**Overview**

This page provides a workflow for machine validation in NVIDIA Infra Controller (NICo).

Machine validation is a process of testing and verifying the hardware components and peripherals of a machine before handing it over to a tenant. The purpose of machine validation is to avoid disruption of tenant usage and ensure that the machine meets the expected benchmarks and performance. Machine validation involves running a series of regression tests and burn-in tests to stress the machine to its maximum capability and identify any potential issues or failures. Machine validation provides several benefits for the tenant. By performing machine validation, NICo ensures that machine is in optimal condition and ready for tenant usage. Machine validation helps to detect and resolve any hardware issues or failures before they affect the tenant's workloads

Machine validation is performed using a different tool, these are available in the discovery image. Most of these tools require root privileges and are non-interactive. The tool(s) runs tests and sends result to Site controller

**Purpose**

End to end user guide for usage of machine validation feature in NICo

**Audience**

SRE, Provider admin, Developer

**Prerequisites**

1) Access to NICo sites

# Features and Functionalities

## **Features**

#### Feature gate

The NICo site controller has site settings. These settings provide mechanisms to enable and disable features. Machine Validation feature controlled using these settings.  The feature gate enables or disables machine validation features at deploy time.

#### Test case management

Test Case Management is the process of  adding, updating test cases. There are two types of test cases

1) Test cases added during deploy- These are common across all the sites and these are read-only test cases. Test cases are added through NICo DB migration.
2) Site specific test case - Added by site admin

#### Enable disable test

If the test case is enabled then forge-scout selects the test case for running.

#### Verify tests

If site admin adds a test case, by default the test case verified flag will be set to false. The term verify means test case added to NICo datastore but not actually verified on hardware. By default the forge-scout never runs unverified test cases. Using on-demand machine validation, admin can run unverified test cases.

#### View tests results

Once the forge-scout completes the test cases, the view results feature gives a detailed report of executed test cases.

#### On Demand tests

If the machine is not allocated for long and the machine remains in ready state, the site admin can run the On-Demand testing. Here the selected tests will run.


### List of test cases

```bash
| TestId                   | Name               | Command                    | Timeout | IsVerified | Version              | IsEnabled |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_CpuBenchmarkingFp  | CpuBenchmarkingFp  | /benchpress/benchpress     | 7200    | true       | V1-T1734600519831720 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_CpuBenchmarkingInt | CpuBenchmarkingInt | /benchpress/benchpress     | 7200    | true       | V1-T1734600519831720 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_CudaSample         | CudaSample         | /opt/benchpress/benchpress | 7200    | true       | V1-T1734600519831720 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_FioFile            | FioFile            | /opt/benchpress/benchpress | 7200    | true       | V1-T1734600519831720 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_FioPath            | FioPath            | /opt/benchpress/benchpress | 7200    | true       | V1-T1734600519831720 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_FioSSD             | FioSSD             | /opt/benchpress/benchpress | 7200    | true       | V1-T1734600519831720 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_MmMemBandwidth     | MmMemBandwidth     | /benchpress/benchpress     | 7200    | true       | V1-T1734600519831720 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_MmMemLatency       | MmMemLatency       | /benchpress/benchpress     | 7200    | true       | V1-T1734600519831720 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_MmMemPeakBandwidth | MmMemPeakBandwidth | /benchpress/benchpress     | 7200    | true       | V1-T1734600519831720 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_Nvbandwidth        | Nvbandwidth        | /opt/benchpress/benchpress | 7200    | true       | V1-T1734600519831720 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_RaytracingVk       | RaytracingVk       | /opt/benchpress/benchpress | 7200    | true       | V1-T1734600519831720 | false     |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_CPUTestLong        | CPUTestLong        | stress-ng                  | 7200    | true       | V1-T1731386879991534 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_CPUTestShort       | CPUTestShort       | stress-ng                  | 7200    | true       | V1-T1731386879991534 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_MemoryTestLong     | MemoryTestLong     | stress-ng                  | 7200    | true       | V1-T1731386879991534 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_MemoryTestShort    | MemoryTestShort    | stress-ng                  | 7200    | true       | V1-T1731386879991534 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_MqStresserLong     | MqStresserLong     | stress-ng                  | 7200    | true       | V1-T1731386879991534 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_MqStresserShort    | MqStresserShort    | stress-ng                  | 7200    | true       | V1-T1731386879991534 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_DcgmFullShort      | DcgmFullShort      | dcgmi                      | 7200    | true       | V1-T1731384539962561 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_DefaultTestCase    | DefaultTestCase    | echo                       | 7200    | false      | V1-T1731384539962561 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_DcgmFullLong       | DcgmFullLong       | dcgmi                      | 7200    | true       | V1-T1731383523746813 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_ForgeRunBook       | ForgeRunBook       |                            | 7200    | true       | V1-T1731382251768493 | false     |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+
```

## **How to use Machine Validation feature**

### Initial setup

NICo has a Machine validation feature gate. By default the feature is disabled.

To enable this feature, add the following section in the API site config TOML file (`/site/site-controller/files/carbide-api/carbide-api-site-config.toml`):

```toml
[machine_validation_config]
enabled = true
```

Machine Validation allows site operators to configure the NGC container registry

Finally add the config to the site:

```bash
user:~$ carbide-admin-cli machine-validation external-config    add-update --name container_auth --description "NVCR description"  --file-name /tmp/config.json
```

> **Note**: You can copy the Imagepullsecret from Kubernetes with the command `kubectl get secrets -n forge-system imagepullsecret -o yaml | awk '$1==".dockerconfigjson:" {print $2}'`.

### Enable test cases

By default all the test cases are disabled.

```bash
user@host:admin$ carbide-admin-cli machine-validation tests show

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| TestId                   | Name               | Command                    | Timeout | IsVerified | Version              | IsEnabled |

+==========================+====================+============================+=========+============+======================+===========+

| forge_CpuBenchmarkingFp  | CpuBenchmarkingFp  | /benchpress/benchpress     | 7200    | true       | V1-T1734600519831720 | false     |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_CpuBenchmarkingInt | CpuBenchmarkingInt | /benchpress/benchpress     | 7200    | true       | V1-T1734600519831720 | false     |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| forge_CudaSample         | CudaSample         | /opt/benchpress/benchpress | 7200    | true       | V1-T1734600519831720 | false     |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+
```

To enable tests

```bash
carbide-admin-cli machine-validation tests enable --test-id <test_id> --version  <test version>

carbide-admin-cli machine-validation tests verify --test-id <test_id> --version  <test version>
```

Note: There is a bug, a workaround is to use two commands. Will be fixed in coming releases.

For example, to enable forge_CudaSample, execute following steps:

```
user@host:admin$ carbide-admin-cli machine-validation tests enable --test-id forge_CudaSample  --version  V1-T1734600519831720

user@host:admin$ carbide-admin-cli machine-validation tests verify --test-id forge_CudaSample  --version  V1-T1734600519831720
```

Enabling different tests cases

CPU Benchmarking test cases

1) forge_CpuBenchmarkingFp

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_CpuBenchmarkingFp  --version  V1-T1734600519831720

carbide-admin-cli machine-validation tests verify --test-id forge_CpuBenchmarkingFp  --version  V1-T1734600519831720
```

2) forge_CpuBenchmarkingInt

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_CpuBenchmarkingInt --version  V1-T1734600519831720

carbide-admin-cli machine-validation tests verify --test-id forge_CpuBenchmarkingInt --version  V1-T1734600519831720
```

Cuda sample test cases

3) forge_CudaSample

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_CudaSample --version  V1-T1734600519831720

carbide-admin-cli machine-validation tests verify --test-id forge_CudaSample --version  V1-T1734600519831720
```

FIO test cases

4) forge_FioFile

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_FioFile --version  V1-T1734600519831720

carbide-admin-cli machine-validation tests verify --test-id forge_FioFile --version  V1-T1734600519831720
```

5) forge_FioPath

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_FioPath --version  V1-T1734600519831720

carbide-admin-cli machine-validation tests verify --test-id forge_FioPath --version  V1-T1734600519831720
```

6) forge_FioSSD

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_FioSSD --version  V1-T1734600519831720

carbide-admin-cli machine-validation tests verify --test-id forge_FioSSD --version  V1-T1734600519831720
```

Memory test cases

7) forge_MmMemBandwidth

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_MmMemBandwidth --version  V1-T1734600519831720

carbide-admin-cli machine-validation tests verify --test-id forge_MmMemBandwidth --version  V1-T1734600519831720
```

8) forge_MmMemLatency

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_MmMemLatency --version  V1-T1734600519831720

carbide-admin-cli machine-validation tests verify --test-id forge_MmMemLatency --version  V1-T1734600519831720
```

9) forge_MmMemPeakBandwidth

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_MmMemPeakBandwidth --version  V1-T1734600519831720

carbide-admin-cli machine-validation tests verify --test-id forge_MmMemPeakBandwidth --version  V1-T1734600519831720
```

NV test cases

10) forge_Nvbandwidth

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_Nvbandwidth --version  V1-T1734600519831720

carbide-admin-cli machine-validation tests verify --test-id forge_Nvbandwidth --version  V1-T1734600519831720
```

Stress ng test cases

11) forge_CPUTestLong

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_CPUTestLong --version  V1-T1731386879991534

carbide-admin-cli machine-validation tests verify --test-id forge_CPUTestLong --version  V1-T1731386879991534
```

12) forge_CPUTestShort

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_CPUTestShort --version  V1-T1731386879991534

carbide-admin-cli machine-validation tests verify --test-id forge_CPUTestShort --version  V1-T1731386879991534
```

13) forge_MemoryTestLong

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_MemoryTestLong  --version  V1-T1731386879991534

carbide-admin-cli machine-validation tests verify --test-id forge_MemoryTestLong  --version  V1-T1731386879991534
```

14) forge_MemoryTestShort

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_MemoryTestShort  --version  V1-T1731386879991534

carbide-admin-cli machine-validation tests verify --test-id forge_MemoryTestShort  --version  V1-T1731386879991534
```

15) forge_MqStresserLong

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_MqStresserLong  --version  V1-T1731386879991534

carbide-admin-cli machine-validation tests verify --test-id forge_MqStresserShort  --version  V1-T1731386879991534
```

16) forge_MqStresserShort

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_MqStresserShort  --version  V1-T1731386879991534

carbide-admin-cli machine-validation tests verify --test-id forge_MqStresserShort  --version  V1-T1731386879991534
```

DCGMI test cases

17) forge_DcgmFullShort

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_DcgmFullShort  --version  V1-T1731384539962561

carbide-admin-cli machine-validation tests verify --test-id forge_DcgmFullLong  --version  V1-T1731384539962561
```

18) forge_DcgmFullLong

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_DcgmFullLong  --version  V1-T1731383523746813

carbide-admin-cli machine-validation tests verify --test-id forge_DcgmFullLong  --version  V1-T1731383523746813
```

Shoreline Agent test case

19) forge_ForgeRunBook

```bash
carbide-admin-cli machine-validation tests enable --test-id forge_ForgeRunBook --version  V1-T1731383523746813

carbide-admin-cli machine-validation tests verify --test-id forge_ForgeRunBook  --version  V1-T1731383523746813
```

### Verify tests

If a test is modified or added by site admin by default the test case verify flag is set to false

```bash
user@host:admin$ carbide-admin-cli machine-validation tests show

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

| TestId                   | Name               | Command                    | Timeout | IsVerified | Version              | IsEnabled |

+==========================+====================+============================+=========+============+======================+===========+

| forge_site_admin         | site               | echo                       | 7200    | false      | V1-T1734009539861341 | true      |

+--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+
```

To mark test as verified

```bash
carbide-admin-cli machine-validation tests verify --test-id <test_id> --version  <test version>
```

Eg:  To enable forge_CudaSample  execute following steps

```bash
user@host:admin$ carbide-admin-cli machine-validation tests verify --test-id forge_site_admin --version  V1-T1734009539861341
```

### Add test case

Site admin can add test cases per site.

```bash
user@host:admin$ carbide-admin-cli machine-validation tests add  --help
```

Add new test case

Usage: `carbide-admin-cli machine-validation tests add [OPTIONS] --name <NAME> --command <COMMAND> --args <ARGS>`

Options:

```bash
  --name <NAME>

      Name of the test case

  --command <COMMAND>

      Command of the test case

  --args <ARGS>

      Args for command

  --contexts <CONTEXTS>

      List of contexts

  --img-name <IMG_NAME>

      Container image name

  --execute-in-host <EXECUTE_IN_HOST>

      Run command using chroot in case of container [possible values: true, false]

  --container-arg <CONTAINER_ARG>

      Container args

  --description <DESCRIPTION>

      Description

  --extra-err-file <EXTRA_ERR_FILE>

      Command output error file

  --extended

      Extended result output.

  --extra-output-file <EXTRA_OUTPUT_FILE>

      Command output file

  --external-config-file <EXTERNAL_CONFIG_FILE>

      External file

  --pre-condition <PRE_CONDITION>

      Pre condition

  --timeout <TIMEOUT>

      Command Timeout

  --supported-platforms <SUPPORTED_PLATFORMS>

      List of supported platforms

  --custom-tags <CUSTOM_TAGS>

      List of custom tags

  --components <COMPONENTS>

      List of system components

  --is-enabled <IS_ENABLED>

      Enable the test [possible values: true, false]

  --read-only <READ_ONLY>

      Is read-only [possible values: true, false]

-h, --help

      Print help
```

Eg: add test case which prints **‘newtest’**

```bash
user@host:admin$ carbide-admin-cli machine-validation tests add   --name NewTest --command echo --args newtest

user@host:admin$ carbide-admin-cli machine-validation tests show --test-id forge_NewTest

+---------------+---------+---------+---------+------------+----------------------+-----------+

| TestId        | Name    | Command | Timeout | IsVerified | Version              | IsEnabled |

+===============+=========+=========+=========+============+======================+===========+

| forge_NewTest | NewTest | echo    | 7200    | false      | V1-T1736492939564126 | true      |

+---------------+---------+---------+---------+------------+----------------------+-----------+
```

By default the test case’s verify flag is set to false. Set

```bash
user@host:admin$ carbide-admin-cli machine-validation tests verify  --test-id forge_NewTest --version V1-T1736492939564126

user@host:admin$ carbide-admin-cli machine-validation tests show --test-id forge_NewTest

+---------------+---------+---------+---------+------------+----------------------+-----------+

| TestId        | Name    | Command | Timeout | IsVerified | Version              | IsEnabled |

+===============+=========+=========+=========+============+======================+===========+

| forge_NewTest | NewTest | echo    | 7200    | true       | V1-T1736492939564126 | true      |

+---------------+---------+---------+---------+------------+----------------------+-----------+
```

### Update test case

Update existing testcases

```bash
user@host:admin$ carbide-admin-cli machine-validation tests update --help
```

Update existing test case

Usage: `carbide-admin-cli machine-validation tests update [OPTIONS] --test-id <TEST_ID> --version <VERSION>`

Options:

```bash
--test-id <TEST_ID>

    Unique identification of the test

--version <VERSION>

    Version to be verify

--contexts <CONTEXTS>

    List of contexts

--img-name <IMG_NAME>

    Container image name

--execute-in-host <EXECUTE_IN_HOST>

    Run command using chroot in case of container [possible values: true, false]

--container-arg <CONTAINER_ARG>

    Container args

--description <DESCRIPTION>

    Description

--command <COMMAND>

    Command

--args <ARGS>

    Command args

--extended

    Extended result output.

--extra-err-file <EXTRA_ERR_FILE>

    Command output error file

--extra-output-file <EXTRA_OUTPUT_FILE>

    Command output file

--external-config-file <EXTERNAL_CONFIG_FILE>

    External file

--pre-condition <PRE_CONDITION>

    Pre condition

--timeout <TIMEOUT>

    Command Timeout

--supported-platforms <SUPPORTED_PLATFORMS>

    List of supported platforms

--custom-tags <CUSTOM_TAGS>

    List of custom tags

--components <COMPONENTS>

    List of system components

--is-enabled <IS_ENABLED>

    Enable the test [possible values: true, false]

  -h, --help

    Print help
```

We can selectively update fields of test cases. Once the test case is updated the verify flag is set to false. Site admin hs to explicitly set the flag as verified.

```bash
user@host:admin$ carbide-admin-cli machine-validation tests update  --test-id forge_NewTest --version V1-T1736492939564126 --args updatenewtest

user@host:admin$ carbide-admin-cli machine-validation tests show --test-id forge_NewTest

+---------------+---------+---------+---------+------------+----------------------+-----------+

| TestId        | Name    | Command | Timeout | IsVerified | Version              | IsEnabled |

+===============+=========+=========+=========+============+======================+===========+

| forge_NewTest | NewTest | echo    | 7200    | false      | V1-T1736492939564126 | true      |

+---------------+---------+---------+---------+------------+----------------------+-----------+

user@host:admin$ carbide-admin-cli machine-validation tests verify  --test-id forge_NewTest --version V1-T1736492939564126

user@host:admin$ carbide-admin-cli machine-validation tests show --test-id forge_NewTest

+---------------+---------+---------+---------+------------+----------------------+-----------+

| TestId        | Name    | Command | Timeout | IsVerified | Version              | IsEnabled |

+===============+=========+=========+=========+============+======================+===========+

| forge_NewTest | NewTest | echo    | 7200    | true       | V1-T1736492939564126 | true      |

+---------------+---------+---------+---------+------------+----------------------+-----------+
```

### Run On-Demand Validation

Machine validation has 3 Contexts

1) Discovery - Tests cases with this context will be executed during node ingestion time.
2) Cleanup - Tests cases with context will be executed during node cleanup(between tenants).
3) On-Demand - Tests cases with context will be executed when on demand machine validation is triggered.

```bash
user@host:admin$ carbide-admin-cli machine-validation on-demand start  --help
```

Start on demand machine validation

Usage: `carbide-admin-cli machine-validation on-demand start [OPTIONS] --machine <MACHINE>`

Options:

```bash
    --help

-m, --machine <MACHINE>              Machine id for start validation

  --tags <TAGS>                    Results history

  --allowed-tests <ALLOWED_TESTS>  Allowed tests

  --run-unverfied-tests            Run un verified tests

  --contexts <CONTEXTS>            Contexts

  --extended                       Extended result output.
```

Usecase 1 - Run tests whose context is on-demand

```bash
user@host:admin$ carbide-admin-cli machine-validation on-demand start -m fm100htq54dmt805ck6k95dfd44itsufqiidd4acrdt811t92hvvlacm8gg
```

Usecase 2 - Run tests whose context is Discovery

```bash
user@host:admin$ carbide-admin-cli machine-validation on-demand start -m fm100htq54dmt805ck6k95dfd44itsufqiidd4acrdt811t92hvvlacm8gg --contexts Discovery
```

Usecase 3 - Run a specific test case

```bash
user@host:admin$ carbide-admin-cli machine-validation on-demand start -m fm100htq54dmt805ck6k95dfd44itsufqiidd4acrdt811t92hvvlacm8gg  --allowed-tests  forge_CudaSample
```

Usecase 4 - Run un verified forge_CudaSample test case

```bash
user@host:admin$ carbide-admin-cli machine-validation on-demand start -m fm100htq54dmt805ck6k95dfd44itsufqiidd4acrdt811t92hvvlacm8gg   --run-unverfied-tests  --allowed-tests  forge_CudaSample
```

### View results

Feature shows progress of the on-going machine validation

```bash
user@host:admin$ carbide-admin-cli machine-validation runs show --help
```

Show Runs


Usage: `carbide-admin-cli machine-validation runs show [OPTIONS]`

Options:
```bash

-m, --machine <MACHINE>  Show machine validation runs of a machine

    --history            run history

    --extended           Extended result output.

-h, --help               Print help

user@host:admin$ carbide-admin-cli machine-validation runs show   -m fm100htq54dmt805ck6k95dfd44itsufqiidd4acrdt811t92hvvlacm8gg

+--------------------------------------+-------------------------------------------------------------+-----------------------------+-----------------------------+-----------+------------------------+

| Id                                   | MachineId                                                   | StartTime                   | EndTime

    | Context   | State                  |

+======================================+=============================================================+=============================+=============================+===========+========================+

| b8df2faf-dc6e-402d-90ca-781c63e380b9 | fm100htq54dmt805ck6k95dfd44itsufqiidd4acrdt811t92hvvlacm8gg | 2024-12-02T22:54:47.997398Z | 2024-12-02T23:22:00.396804Z | Discovery | InProgress(InProgress) |

+--------------------------------------+-------------------------------------------------------------+-----------------------------+-----------------------------+-----------+------------------------+

| 539cea32-60ae-4863-8991-8b8e3c726717 | fm100htq54dmt805ck6k95dfd44itsufqiidd4acrdt811t92hvvlacm8gg | 2025-01-09T14:12:23.243324Z | 2025-01-09T16:51:32.110006Z | OnDemand  | Completed(Success)     |

+--------------------------------------+-------------------------------------------------------------+-----------------------------+-----------------------------+-----------+------------------------+
```

To view individual completed test results, by default the result command shows only last run tests in each individual context**(Discovery,Ondemand, Cleanup)**.

```bash
user@host:admin$ carbide-admin-cli machine-validation results show --help
```

Show results

Usage: `carbide-admin-cli machine-validation results show [OPTIONS] <--validation-id <VALIDATION_ID>|--test-name <TEST_NAME>|--machine <MACHINE>>`

Options:

```bash
-m, --machine <MACHINE>              Show machine validation result of a machine

-v, --validation-id <VALIDATION_ID>  Machine validation id

-t, --test-name <TEST_NAME>          Name of the test case

    --history                        Results history

    --extended                       Extended result output.

-h, --help                           Print help

user@host:admin$ carbide-admin-cli machine-validation results   show   -m fm100htq54dmt805ck6k95dfd44itsufqiidd4acrdt811t92hvvlacm8gg

+--------------------------------------+----------------+-----------+----------+-----------------------------+-----------------------------+

| RunID                                | Name           | Context   | ExitCode | StartTime                   | EndTime                     |

+======================================+================+===========+==========+=============================+=============================+

| b8df2faf-dc6e-402d-90ca-781c63e380b9 | CPUTestLong    | Discovery | 0        | 2024-12-02T23:08:04.063057Z | 2024-12-02T23:10:03.463683Z |

+--------------------------------------+----------------+-----------+----------+-----------------------------+-----------------------------+

| b8df2faf-dc6e-402d-90ca-781c63e380b9 | MemoryTestLong | Discovery | 0        | 2024-12-02T23:10:03.533416Z | 2024-12-02T23:12:06.060216Z |

+--------------------------------------+----------------+-----------+----------+-----------------------------+-----------------------------+

| b8df2faf-dc6e-402d-90ca-781c63e380b9 | MqStresserLong | Discovery | 0        | 2024-12-02T23:12:06.134385Z | 2024-12-02T23:14:07.589445Z |

+--------------------------------------+----------------+-----------+----------+-----------------------------+-----------------------------+

| b8df2faf-dc6e-402d-90ca-781c63e380b9 | DcgmFullLong   | Discovery | 0        | 2024-12-02T23:14:07.801503Z | 2024-12-02T23:20:11.166087Z |

+--------------------------------------+----------------+-----------+----------+-----------------------------+-----------------------------+

| b8df2faf-dc6e-402d-90ca-781c63e380b9 | ForgeRunBook   | Discovery | 0        | 2024-12-02T23:20:30.427153Z | 2024-12-02T23:22:00.202657Z |

+--------------------------------------+----------------+-----------+----------+-----------------------------+-----------------------------+

| 539cea32-60ae-4863-8991-8b8e3c726717 | CudaSample     | OnDemand  | 0        | 2025-01-09T16:51:09.046537Z | 2025-01-09T16:51:32.611098Z |

+--------------------------------------+----------------+-----------+----------+-----------------------------+-----------------------------+
```

### How to add new platform support

To add a new platform for individual tests

1) Get system sku id-

```bash
# dmidecode -s system-sku-number | tr "[:upper:]" "[:lower:]"
```
2)

```bash
# carbide-admin-cli machine-validation tests update  --test-id  <test_id> --version   <test version> --supported-platforms    <sku>

For example:
```
# carbide-admin-cli machine-validation tests update  --test-id  forge_default  --version   V1-T1734009539861341   --supported-platforms    7d9ectOlww
```

