User Guide for Machine Validation
=================================


Table of Contents

[**Getting Started**](#getting-started)

[**Features and Functionalities**](#features-and-functionalities)

[***Features***](#features)

[Feature gate](#feature-gate)

[Test case management](#test-case-management)

[Enable disable test](#enable-disable-test)

[Verify tests](#verify-tests)

[View tests results](#view-tests-results)

[On Demand tests](#on-demand-tests)

[List of test cases](#list-of-test-cases)

[How to use Machine Validation feature](#how-to-use-machine-validation-feature)

[Initial setup](#initial-setup)

[Enable test cases](#enable-test-cases)

[Verify tests](#verify-tests)

[Add test case](#add-test-case)

[Update test case](#update-test-case)

[Run On-Demand Validation](#run-on-demand-validation)

[View results](#view-results)

[How to add new platform support?](#how-to-add-new-platform-support?)

[**Troubleshooting**](#troubleshooting)

[**Frequently Asked Questions (FAQs)**](#frequently-asked-questions-(faqs))

[**Contact and Support**](#contact-and-support)

[**References**](#references)

# Getting Started {#getting-started}

**Overview**

Machine validation is a process of testing and verifying the hardware components and peripherals of a machine before handing it over to a tenant. The purpose of machine validation is to avoid disruption of tenant usage and ensure that the machine meets the expected benchmarks and performance. Machine validation involves running a series of regression tests and burn-in tests to stress the machine to its maximum capability and identify any potential issues or failures. Machine validation provides several benefits for the tenant. By performing machine validation, forge ensures that machine is in optimal condition and ready for tenant usage. Machine validation @ forge helps to detect and resolve any hardware issues or failures before they affect the tenant's workloads

Machine validation is performed using a different tool, these are available in the discovery image. Most of these tools require root privileges and are non-interactive. The tool(s) runs tests and sends result to Site controller

**Purpose**

End to end user guide for usage of machine validation feature in forge

**Audience**

SRE, Provider admin, Developer

**Prerequisites**

1) Access to forge sites

#####

# Features and Functionalities {#features-and-functionalities}

## **Features** {#features}

#### Feature gate {#feature-gate}

Carbide site controller has site settings. These settings provide mechanisms to enable and disable features. Machine Validation feature controlled using these settings.  The feature gate enables or disables machine validation features at deploy time.

#### Test case management {#test-case-management}

Test Case Management is the process of  adding, updating test cases. There are two types of test cases

1) Test cases added during deploy- These are common across all the sites and these are read-only test cases. Test cases are added through forge DB migration.
2) Site specific test case - Added by site admin

#### Enable disable test {#enable-disable-test}

If the test case is enabled then forge-scout selects the test case for running.

#### Verify tests {#verify-tests}

If site admin adds a test case, by default the test case verified flag will be set to false. The term verify means test case added to forge datastore but not actually verified on hardware. By default the forge-scout never runs unverified test cases. Using on-demand machine validation, admin can run unverified test cases.

#### View tests results {#view-tests-results}

Once the forge-scout completes the test cases, the view results feature gives a detailed report of executed test cases.

#### On Demand tests {#on-demand-tests}

If the machine is not allocated for long and the machine remains in ready state, the site admin can run the On-Demand testing. Here the selected tests will run.


### List of test cases {#list-of-test-cases}

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

## **How to use Machine Validation feature** {#how-to-use-machine-validation-feature}

### Initial setup {#initial-setup}

Carbide has a Machine validation feature gate. By default the feature is disabled.

To enable add below section in api site config toml [forged/](https://gitlab-master.nvidia.com/nvmetal/forged/-/tree/main/envs/)<name>/site/site-controller/files/carbide-api/carbide-api-site-config.toml

[machine_validation_config]
enabled = true

Machine Validation allows site operators to configure the NGC container registry.  This allows machine validation to use private container in

Finally add the config to site

    user:~$ carbide-admin-cli machine-validation external-config    add-update --name container_auth --description "NVCR description"  --file-name /tmp/config.json

 Note: One can copy Imagepullsecret from Kubernetes - **kubectl get secrets -n forge-system imagepullsecret -o yaml | awk '$1==".dockerconfigjson:" {print $2}'**

### Enable test cases {#enable-test-cases}

By default all the test cases are disabled.

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

To enable tests

    carbide-admin-cli machine-validation tests enable --test-id <test_id> --version  <test version>

    carbide-admin-cli machine-validation tests verify --test-id <test_id> --version  <test version>

    Note: There is a bug, a workaround is to use two commands. Will be fixed in coming releases.

    Eg:  To enable forge_CudaSample  execute following steps

    user@host:admin$ carbide-admin-cli machine-validation tests enable --test-id forge_CudaSample  --version  V1-T1734600519831720

    user@host:admin$ carbide-admin-cli machine-validation tests verify --test-id forge_CudaSample  --version  V1-T1734600519831720

Enabling different tests cases

CPU Benchmarking test cases

1) forge_CpuBenchmarkingFp

        carbide-admin-cli machine-validation tests enable --test-id forge_CpuBenchmarkingFp  --version  V1-T1734600519831720

        carbide-admin-cli machine-validation tests verify --test-id forge_CpuBenchmarkingFp  --version  V1-T1734600519831720

2) forge_CpuBenchmarkingInt

        carbide-admin-cli machine-validation tests enable --test-id forge_CpuBenchmarkingInt --version  V1-T1734600519831720

        carbide-admin-cli machine-validation tests verify --test-id forge_CpuBenchmarkingInt --version  V1-T1734600519831720

Cuda sample test cases

3) forge_CudaSample

        carbide-admin-cli machine-validation tests enable --test-id forge_CudaSample --version  V1-T1734600519831720

        carbide-admin-cli machine-validation tests verify --test-id forge_CudaSample --version  V1-T1734600519831720

FIO test cases

4) forge_FioFile

        carbide-admin-cli machine-validation tests enable --test-id forge_FioFile --version  V1-T1734600519831720

        carbide-admin-cli machine-validation tests verify --test-id forge_FioFile --version  V1-T1734600519831720

5) forge_FioPath

        carbide-admin-cli machine-validation tests enable --test-id forge_FioPath --version  V1-T1734600519831720

        carbide-admin-cli machine-validation tests verify --test-id forge_FioPath --version  V1-T1734600519831720

6) forge_FioSSD

        carbide-admin-cli machine-validation tests enable --test-id forge_FioSSD --version  V1-T1734600519831720

        carbide-admin-cli machine-validation tests verify --test-id forge_FioSSD --version  V1-T1734600519831720

Memory test cases

7) forge_MmMemBandwidth

        carbide-admin-cli machine-validation tests enable --test-id forge_MmMemBandwidth --version  V1-T1734600519831720

        carbide-admin-cli machine-validation tests verify --test-id forge_MmMemBandwidth --version  V1-T1734600519831720

8) forge_MmMemLatency

        carbide-admin-cli machine-validation tests enable --test-id forge_MmMemLatency --version  V1-T1734600519831720

        carbide-admin-cli machine-validation tests verify --test-id forge_MmMemLatency --version  V1-T1734600519831720

9) forge_MmMemPeakBandwidth

        carbide-admin-cli machine-validation tests enable --test-id forge_MmMemPeakBandwidth --version  V1-T1734600519831720

        carbide-admin-cli machine-validation tests verify --test-id forge_MmMemPeakBandwidth --version  V1-T1734600519831720

NV test cases

10) forge_Nvbandwidth

        carbide-admin-cli machine-validation tests enable --test-id forge_Nvbandwidth --version  V1-T1734600519831720

        carbide-admin-cli machine-validation tests verify --test-id forge_Nvbandwidth --version  V1-T1734600519831720

Stress ng test cases

11) forge_CPUTestLong

        carbide-admin-cli machine-validation tests enable --test-id forge_CPUTestLong --version  V1-T1731386879991534

        carbide-admin-cli machine-validation tests verify --test-id forge_CPUTestLong --version  V1-T1731386879991534

12) forge_CPUTestShort

        carbide-admin-cli machine-validation tests enable --test-id forge_CPUTestShort --version  V1-T1731386879991534

        carbide-admin-cli machine-validation tests verify --test-id forge_CPUTestShort --version  V1-T1731386879991534

13) forge_MemoryTestLong

        carbide-admin-cli machine-validation tests enable --test-id forge_MemoryTestLong  --version  V1-T1731386879991534

        carbide-admin-cli machine-validation tests verify --test-id forge_MemoryTestLong  --version  V1-T1731386879991534

14) forge_MemoryTestShort

        carbide-admin-cli machine-validation tests enable --test-id forge_MemoryTestShort  --version  V1-T1731386879991534

        carbide-admin-cli machine-validation tests verify --test-id forge_MemoryTestShort  --version  V1-T1731386879991534

15) forge_MqStresserLong

        carbide-admin-cli machine-validation tests enable --test-id forge_MqStresserLong  --version  V1-T1731386879991534

        carbide-admin-cli machine-validation tests verify --test-id forge_MqStresserShort  --version  V1-T1731386879991534

16) forge_MqStresserShort

        carbide-admin-cli machine-validation tests enable --test-id forge_MqStresserShort  --version  V1-T1731386879991534

        carbide-admin-cli machine-validation tests verify --test-id forge_MqStresserShort  --version  V1-T1731386879991534

DCGMI test cases

17) forge_DcgmFullShort

        carbide-admin-cli machine-validation tests enable --test-id forge_DcgmFullShort  --version  V1-T1731384539962561

        carbide-admin-cli machine-validation tests verify --test-id forge_DcgmFullLong  --version  V1-T1731384539962561

18) forge_DcgmFullLong

        carbide-admin-cli machine-validation tests enable --test-id forge_DcgmFullLong  --version  V1-T1731383523746813

        carbide-admin-cli machine-validation tests verify --test-id forge_DcgmFullLong  --version  V1-T1731383523746813

Shoreline Agent test case

19) forge_ForgeRunBook

        carbide-admin-cli machine-validation tests enable --test-id forge_ForgeRunBook --version  V1-T1731383523746813

        carbide-admin-cli machine-validation tests verify --test-id forge_ForgeRunBook  --version  V1-T1731383523746813

###

### Verify tests {#verify-tests-1}

If a test is modified or added by site admin by default the test case verify flag is set to false

        user@host:admin$ carbide-admin-cli machine-validation tests show

        +--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

        | TestId                   | Name               | Command                    | Timeout | IsVerified | Version              | IsEnabled |

        +==========================+====================+============================+=========+============+======================+===========+

        | forge_site_admin         | site               | echo                       | 7200    | false      | V1-T1734009539861341 | true      |

        +--------------------------+--------------------+----------------------------+---------+------------+----------------------+-----------+

To mark test as verified

        carbide-admin-cli machine-validation tests verify --test-id <test_id> --version  <test version>

Eg:  To enable forge_CudaSample  execute following steps

    user@host:admin$ carbide-admin-cli machine-validation tests verify --test-id forge_site_admin --version  V1-T1734009539861341

###

### Add test case {#add-test-case}

Site admin can add test cases per site.

        user@host:admin$ carbide-admin-cli machine-validation tests add  --help

Add new test case

Usage: carbide-admin-cli machine-validation tests add [OPTIONS] --name <NAME> --command <COMMAND> --args <ARGS>

Options:

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

Eg: add test case which prints **‘newtest’**

        user@host:admin$ carbide-admin-cli machine-validation tests add   --name NewTest --command echo --args newtest

        user@host:admin$ carbide-admin-cli machine-validation tests show --test-id forge_NewTest

        +---------------+---------+---------+---------+------------+----------------------+-----------+

        | TestId        | Name    | Command | Timeout | IsVerified | Version              | IsEnabled |

        +===============+=========+=========+=========+============+======================+===========+

        | forge_NewTest | NewTest | echo    | 7200    | false      | V1-T1736492939564126 | true      |

        +---------------+---------+---------+---------+------------+----------------------+-----------+

By default the test case’s verify flag is set to false. Set

        user@host:admin$ carbide-admin-cli machine-validation tests verify  --test-id forge_NewTest --version V1-T1736492939564126

        user@host:admin$ carbide-admin-cli machine-validation tests show --test-id forge_NewTest

        +---------------+---------+---------+---------+------------+----------------------+-----------+

        | TestId        | Name    | Command | Timeout | IsVerified | Version              | IsEnabled |

        +===============+=========+=========+=========+============+======================+===========+

        | forge_NewTest | NewTest | echo    | 7200    | true       | V1-T1736492939564126 | true      |

        +---------------+---------+---------+---------+------------+----------------------+-----------+

###

### Update test case {#update-test-case}

Update existing testcases

        user@host:admin$ carbide-admin-cli machine-validation tests update --help

Update existing test case

Usage: carbide-admin-cli machine-validation tests update [OPTIONS] --test-id <TEST_ID> --version <VERSION>

Options:

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

We can selectively update fields of test cases. Once the test case is updated the verify flag is set to false. Site admin hs to explicitly set the flag as verified.

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

        user@host:admin$

###

### Run On-Demand Validation {#run-on-demand-validation}

Machine validation has 3 Contexts

1) Discovery - Tests cases with this context will be executed during node ingestion time.
2) Cleanup - Tests cases with context will be executed during node cleanup(between tenants).
3) On-Demand - Tests cases with context will be executed when on demand machine validation is triggered.

        user@host:admin$ carbide-admin-cli machine-validation on-demand start  --help

Start on demand machine validation

    Usage: carbide-admin-cli machine-validation on-demand start [OPTIONS] --machine <MACHINE>

    Options:

        --help

    -m, --machine <MACHINE>              Machine id for start validation

      --tags <TAGS>                    Results history

      --allowed-tests <ALLOWED_TESTS>  Allowed tests

      --run-unverfied-tests            Run un verified tests

      --contexts <CONTEXTS>            Contexts

      --extended                       Extended result output.

Usecase 1 - Run tests whose context is on-demand

        user@host:admin$ carbide-admin-cli machine-validation on-demand start -m fm100htq54dmt805ck6k95dfd44itsufqiidd4acrdt811t92hvvlacm8gg

Usecase 2 - Run tests whose context is Discovery

        user@host:admin$ carbide-admin-cli machine-validation on-demand start -m fm100htq54dmt805ck6k95dfd44itsufqiidd4acrdt811t92hvvlacm8gg --contexts Discovery

Usecase 3 - Run a specific test case

        user@host:admin$ carbide-admin-cli machine-validation on-demand start -m fm100htq54dmt805ck6k95dfd44itsufqiidd4acrdt811t92hvvlacm8gg  --allowed-tests  forge_CudaSample

Usecase 4 - Run un verified forge_CudaSample test case

        user@host:admin$ carbide-admin-cli machine-validation on-demand start -m fm100htq54dmt805ck6k95dfd44itsufqiidd4acrdt811t92hvvlacm8gg   --run-unverfied-tests  --allowed-tests  forge_CudaSample

### View results {#view-results}

Feature shows progress of the on-going machine validation

        user@host:admin$ carbide-admin-cli machine-validation runs show --help

Show Runs

        Usage: carbide-admin-cli machine-validation runs show [OPTIONS]

        Options:

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

To view individual completed test results, by default the result command shows only last run tests in each individual context**(Discovery,Ondemand, Cleanup)**.

        user@host:admin$ carbide-admin-cli machine-validation results show --help

Show results

        Usage: carbide-admin-cli machine-validation results show [OPTIONS] <--validation-id <VALIDATION_ID>|--test-name <TEST_NAME>|--machine <MACHINE>>

        Options:

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

### How to add new platform support?  {#how-to-add-new-platform-support?}

To add a new platform for individual tests

1) Get system sku id-
        # dmidecode -s system-sku-number | tr "[:upper:]" "[:lower:]"
2)
        # carbide-admin-cli machine-validation tests update  --test-id  <test_id> --version   <test version> --supported-platforms    <sku>

        Eg: # carbide-admin-cli machine-validation tests update  --test-id  forge_default  --version   V1-T1734009539861341   --supported-platforms    7d9ectOlww

# Troubleshooting {#troubleshooting}

# Frequently Asked Questions (FAQs) {#frequently-asked-questions-(faqs)}

# Contact and Support {#contact-and-support}

slack #swngc-forge-dev

# References {#references}
