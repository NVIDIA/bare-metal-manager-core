#!/bin/bash

set -eux pipefail
CHART_ROOTDIR=${CI_PROJECT_DIR}/charts
CHARTS_CHANGED=($(awk '/charts/' ${CI_PROJECT_DIR}/CHANGES.txt | cut -d '/' -f1-2 | uniq))

env

# helm repo add ngc $HELM_NGC $HELM_NGC --username=\$oauthtoken --password=$NVCR_PASS
cat > ${CI_PROJECT_DIR}/template.yml <<-'EOF'
variables:
  NVCR_PASS: "${NVCR_PASS}"
  STG_NVCR_PASS: "${STG_NVCR_PASS}"
  HELM_CACHE_HOME: "${HELM_CACHE_HOME}"
  HELM_CONFIG_HOME: "${HELM_CONFIG_HOME}"
  HELM_DATA_HOME: "${HELM_DATA_HOME}"
  HELM_REGISTRY_CONFIG: "${HELM_REGISTRY_CONFIG}"
  HELM_REPOSITORY_CACHE: "${HELM_REPOSITORY_CACHE}"
  HELM_REPOSITORY_CONFIG: "${HELM_REPOSITORY_CONFIG}"
  HELM_PLUGINS: "${HELM_PLUGINS}"
  PARENT_PIPELINE_ID: "${PARENT_PIPELINE_ID}"
  PARENT_COMMIT_BRANCH: "${PARENT_COMMIT_BRANCH}"
  PARENT_DEFAULT_BRANCH: "${PARENT_DEFAULT_BRANCH}"
  PARENT_CI_PIPELINE_SOURCE: "${PARENT_CI_PIPELINE_SOURCE}"
  PARENT_CI_COMMIT_REF_NAME: "${PARENT_CI_COMMIT_REF_NAME}"

.helm:
  script: |
     export HELM_CACHE_HOME="${HELM_CACHE_HOME}"
     export HELM_CONFIG_HOME="${HELM_CONFIG_HOME}"
     export HELM_DATA_HOME="${HELM_DATA_HOME}"
     export HELM_REGISTRY_CONFIG="${HELM_REGISTRY_CONFIG}"
     export HELM_REPOSITORY_CACHE="${HELM_REPOSITORY_CACHE}"
     export HELM_REPOSITORY_CONFIG="${HELM_REPOSITORY_CONFIG}"
     helm env
 
.kubeval:
  when: always
  script: |
    export HELM_CACHE_HOME="${HELM_CACHE_HOME}"
    export HELM_CONFIG_HOME="${HELM_CONFIG_HOME}"
    export HELM_DATA_HOME="${HELM_DATA_HOME}"
    export HELM_REGISTRY_CONFIG="${HELM_REGISTRY_CONFIG}"
    export HELM_REPOSITORY_CACHE="${HELM_REPOSITORY_CACHE}"
    export HELM_REPOSITORY_CONFIG="${HELM_REPOSITORY_CONFIG}"
    helm env
    helm plugin list
    helm kubeval . --forge-color --strict --kube_version ${KUBE_VERSION} $HELM_EXTRAS --skip-kinds "CustomResourceDefinition" -v ${KUBE_VERSION} -s ${KUBEVAL_SCHEMA_LOCATION}
EOF

cat ${CI_PROJECT_DIR}/template.yml

cat > ${CI_PROJECT_DIR}/workflow.yml <<-'EOF'
workflow:
  rules:
    - if: $PARENT_CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $PARENT_COMMIT_BRANCH == $PARENT_DEFAULT_BRANCH && $PARENT_CI_PIPELINE_SOURCE == 'merge_request_event'
      when: never
    - if: $PARENT_COMMIT_BRANCH
    - if: $PARENT_CI_COMMIT_TAG
EOF


for c in "${CHARTS_CHANGED[@]}"; do

echo "Chart dir is ${c}"
base=$(basename ${c})
echo "Basename is ${base}"

cat >> ${CI_PROJECT_DIR}/${base}_stage.yml <<-EOF
stages:
  - lint
  - test
  - review
  - versioning
  - publish
EOF
# Would love to use dotenv reporter here, but
# https://gitlab.com/gitlab-org/gitlab/-/issues/352828
cat >> ${CI_PROJECT_DIR}/${base}_pipeline.yml <<-EOF
lint:${base}:
  variables:
    NVCR_PASS: "${NVCR_PASS}"
    STG_NVCR_PASS: "${STG_NVCR_PASS}"
    HELM_CACHE_HOME: "${HELM_CACHE_HOME}"
    HELM_CONFIG_HOME: "${HELM_CONFIG_HOME}"
    HELM_DATA_HOME: "${HELM_DATA_HOME}"
    HELM_REGISTRY_CONFIG: "${HELM_REGISTRY_CONFIG}"
    HELM_REPOSITORY_CACHE: "${HELM_REPOSITORY_CACHE}"
    HELM_REPOSITORY_CONFIG: "${HELM_REPOSITORY_CONFIG}"
  image: ${CHILD_JOB_IMAGE}
  stage: lint
  script: |
    export HELM_CACHE_HOME="${HELM_CACHE_HOME}"
    export HELM_CONFIG_HOME="${HELM_CONFIG_HOME}"
    export HELM_DATA_HOME="${HELM_DATA_HOME}"
    export HELM_REGISTRY_CONFIG="${HELM_REGISTRY_CONFIG}"
    export HELM_REPOSITORY_CACHE="${HELM_REPOSITORY_CACHE}"
    export HELM_REPOSITORY_CONFIG="${HELM_REPOSITORY_CONFIG}"
    helm env
    cd ${CI_PROJECT_DIR}/${c}
    helm dep update
    helm lint .
    mkdir -p "${CI_PROJECT_DIR}/build"
    helm package -d "${CI_PROJECT_DIR}/build" .
  artifacts:
    paths: 
      - ${CI_PROJECT_DIR}/build
  tags:
    - x86_64
  needs:
   - pipeline: "${PARENT_PIPELINE_ID}"
     job: prep
"test:${base}_Validates_Kubernetes_1.23.16":
  variables:
    NVCR_PASS: "${NVCR_PASS}"
    STG_NVCR_PASS: "${STG_NVCR_PASS}"
    HELM_CACHE_HOME: "${HELM_CACHE_HOME}"
    HELM_CONFIG_HOME: "${HELM_CONFIG_HOME}"
    HELM_DATA_HOME: "${HELM_DATA_HOME}"
    HELM_REGISTRY_CONFIG: "${HELM_REGISTRY_CONFIG}"
    HELM_REPOSITORY_CACHE: "${HELM_REPOSITORY_CACHE}"
    HELM_REPOSITORY_CONFIG: "${HELM_REPOSITORY_CONFIG}"
    HELM_PLUGINS: "${HELM_PLUGINS}"
    KUBE_VERSION: 1.23.16
    KUBEVAL_SCHEMA_LOCATION: "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/master/"
  script: |
    export HELM_CACHE_HOME="${HELM_CACHE_HOME}"
    export HELM_CONFIG_HOME="${HELM_CONFIG_HOME}"
    export HELM_DATA_HOME="${HELM_DATA_HOME}"
    export HELM_REGISTRY_CONFIG="${HELM_REGISTRY_CONFIG}"
    export HELM_REPOSITORY_CACHE="${HELM_REPOSITORY_CACHE}"
    export HELM_REPOSITORY_CONFIG="${HELM_REPOSITORY_CONFIG}"
    export HELM_PLUGINS="${HELM_PLUGINS}"
    helm env
    helm plugin list
    cd ${CI_PROJECT_DIR}/charts/${base}
    helm dep build
    helm kubeval . --force-color --strict --kube-version  \$KUBE_VERSION \$HELM_EXTRAS --skip-kinds "CustomResourceDefinition" -s \${KUBEVAL_SCHEMA_LOCATION}
  stage: test
  image: ${CHILD_JOB_IMAGE}
  tags:
   - x86_64
  needs:
    - pipeline: "${PARENT_PIPELINE_ID}"
      job: prep

dev_publish:${base}:
  variables:
    NVCR_PASS: "${NVCR_PASS}"
    STG_NVCR_PASS: "${STG_NVCR_PASS}"
    HELM_CACHE_HOME: "${HELM_CACHE_HOME}"
    HELM_CONFIG_HOME: "${HELM_CONFIG_HOME}"
    HELM_DATA_HOME: "${HELM_DATA_HOME}"
    HELM_REGISTRY_CONFIG: "${HELM_REGISTRY_CONFIG}"
    HELM_REPOSITORY_CACHE: "${HELM_REPOSITORY_CACHE}"
    HELM_REPOSITORY_CONFIG: "${HELM_REPOSITORY_CONFIG}"
    HELM_PLUGINS: "${HELM_PLUGINS}"
  stage: publish
  image: ${CHILD_JOB_IMAGE}
  tags:
    - x86_64
  script: |
     export HELM_CACHE_HOME="${HELM_CACHE_HOME}"
     export HELM_CONFIG_HOME="${HELM_CONFIG_HOME}"
     export HELM_DATA_HOME="${HELM_DATA_HOME}"
     export HELM_REGISTRY_CONFIG="${HELM_REGISTRY_CONFIG}"
     export HELM_REPOSITORY_CACHE="${HELM_REPOSITORY_CACHE}"
     export HELM_REPOSITORY_CONFIG="${HELM_REPOSITORY_CONFIG}"
     export HELM_PLUGINS="${HELM_PLUGINS}"
     cd ${CI_PROJECT_DIR}/charts/${base}
     helm dep build
     EXTRACTED_VERSION=\$(awk '/^version/ {print \$2}' Chart.yaml)
     sed -ri "s/^version:\s?\$EXTRACTED_VERSION/version: \$VERSION/" Chart.yaml
     mkdir -p "${CI_PROJECT_DIR}/build"
     helm package -d "${CI_PROJECT_DIR}/build" .
     chart_file=\$(ls -l ${CI_PROJECT_DIR}/build/${base}*.tgz | head -n 1 | awk '{print \$NF}')
     echo "FILE IS \$chart_file"
     helm cm-push \$chart_file stgngc
  needs:
    - pipeline: "${PARENT_PIPELINE_ID}"
      job: prep
  artifacts:
    paths:
      - build
  rules:
    - if: \$PARENT_COMMIT_BRANCH == \$PARENT_DEFAULT_BRANCH && \$PARENT_CI_PIPELINE_SOURCE == 'merge_request_event'

prod_publish:${base}:
  variables:
    NVCR_PASS: "${NVCR_PASS}"
    STG_NVCR_PASS: "${STG_NVCR_PASS}"
    HELM_CACHE_HOME: "${HELM_CACHE_HOME}"
    HELM_CONFIG_HOME: "${HELM_CONFIG_HOME}"
    HELM_DATA_HOME: "${HELM_DATA_HOME}"
    HELM_REGISTRY_CONFIG: "${HELM_REGISTRY_CONFIG}"
    HELM_REPOSITORY_CACHE: "${HELM_REPOSITORY_CACHE}"
    HELM_REPOSITORY_CONFIG: "${HELM_REPOSITORY_CONFIG}"
    HELM_PLUGINS: "${HELM_PLUGINS}"
  stage: publish
  image: ${CHILD_JOB_IMAGE}
  tags:
    - x86_64
  script: |
     export HELM_CACHE_HOME="${HELM_CACHE_HOME}"
     export HELM_CONFIG_HOME="${HELM_CONFIG_HOME}"
     export HELM_DATA_HOME="${HELM_DATA_HOME}"
     export HELM_REGISTRY_CONFIG="${HELM_REGISTRY_CONFIG}"
     export HELM_REPOSITORY_CACHE="${HELM_REPOSITORY_CACHE}"
     export HELM_REPOSITORY_CONFIG="${HELM_REPOSITORY_CONFIG}"
     export HELM_PLUGINS="${HELM_PLUGINS}"  cd ${CI_PROJECT_DIR}/charts/${base}
     EXTRACTED_VERSION=\$(awk '/^version/ {print \$2}' Chart.yaml)
     sed -ri "s/^version: \$EXTRACTED_VERSION/version: \$VERSION/" Chart.yaml
     mkdir -p build
     helm dep build
     mkdir -p "${CI_PROJECT_DIR}/build"
     helm package -d "${CI_PROJECT_DIR}/build" .
     chart_file=\$(ls -l ${CI_PROJECT_DIR}/build/${base}*.tgz | head -n 1 | awk '{print \$NF}')
     echo "FILE IS \$chart_file"
  needs:
    - pipeline: "${PARENT_PIPELINE_ID}"
      job: prep
  artifacts:
    paths:
      - build
  rules:
    - if: \$PARENT_CI_COMMIT_TAG
EOF
cat ${CI_PROJECT_DIR}/${base}_pipeline.yml
done


yq -M ea '. as $item ireduce({}; . *+ $item)' ${CI_PROJECT_DIR}/template.yml ${CI_PROJECT_DIR}/workflow.yml ${CI_PROJECT_DIR}/*_stage.yml ${CI_PROJECT_DIR}/*_pipeline.yml > ${CI_PROJECT_DIR}/pipeline.yml
#echo 'task goes here' | cat - todo.txt > temp && mv temp todo.txt
# yq '.stages += .stages' ${CI_PROJECT_DIR}/stages.yml -y | cat - ${CI_PROJECT_DIR}/pipeline.yml > ${CI_PROJECT_DIR}/temp && mv ${CI_PROJECT_DIR}/temp {$CI_PROJECT_DIR}/pipeline.yml

cat "${CI_PROJECT_DIR}/pipeline.yml"
