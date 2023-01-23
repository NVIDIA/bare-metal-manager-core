#!/bin/bash

set -eux pipefail
CHART_ROOTDIR=${CI_PROJECT_DIR}/charts


FORMATTED_CHANGES=($(awk '/charts/' ${CI_PROJECT_DIR}/CHANGES.txt | cut -d '/' -f1-2 | uniq)) 

if [[ "${#FORMATTED_CHANGES[@]}" -ne 0 ]]; then
  CHART_CHANGES="1"
  CHARTS=$FORMATTED_CHANGES
else
  CHART_CHANGES="0"
  CHARTS=($(find charts/ -mindepth 1 -maxdepth 1 -type d))
fi

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
  PARENT_CI_OPEN_MERGE_REQUESTS: "${PARENT_CI_OPEN_MERGE_REQUESTS}"
  PARENT_CI_COMMIT_TAG: ${PARENT_CI_COMMIT_TAG}

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
    - if: $PARENT_COMMIT_BRANCH && $PARENT_CI_OPEN_MERGE_REQUESTS && $PARENT_CI_PIPELINE_SOURCE == "push"
      when: never
    - if: $PARENT_COMMIT_BRANCH == $PARENT_DEFAULT_BRANCH && $PARENT_CI_PIPELINE_SOURCE == 'merge_request_event'
      when: never
    - if: $PARENT_COMMIT_BRANCH
    - if: $PARENT_CI_COMMIT_TAG
EOF

for c in "${CHARTS[@]}"; do

echo "Chart dir is ${c}"
base=$(basename ${c})
echo "Basename is ${base}"

cat >> ${CI_PROJECT_DIR}/${base}_stage.yml <<-EOF
stages:
  - lint
  - test
  - review
  - versioning
  - package
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
    CHART_CHANGES: "${CHART_CHANGES}"
    PARENT_CI_PIPELINE_SOURCE: "${PARENT_CI_PIPELINE_SOURCE}"

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
    helm dep build
    helm lint .
  artifacts:
    paths: 
      - ${CI_PROJECT_DIR}
  tags:
    - x86_64
  needs:
   - pipeline: "${PARENT_PIPELINE_ID}"
     job: prep
  rules:
    - if: \$PARENT_CI_PIPELINE_SOURCE == "merge_request_event"
      changes:
        - "charts/**/*"
    - when: never

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
    PARENT_CI_PIPELINE_SOURCE: "${PARENT_CI_PIPELINE_SOURCE}"
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
    cd ${CI_PROJECT_DIR}/charts/${base}
    helm kubeval . --force-color --strict --kube-version  \$KUBE_VERSION \$HELM_EXTRAS --skip-kinds "CustomResourceDefinition" -s \${KUBEVAL_SCHEMA_LOCATION}
  stage: test
  image: ${CHILD_JOB_IMAGE}
  tags:
   - x86_64
  needs:
    - pipeline: "${PARENT_PIPELINE_ID}"
      job: prep
    - lint:${base}
  rules:
    - if: \$PARENT_CI_PIPELINE_SOURCE == "merge_request_event"
      changes:
        - "charts/**/*"
    - when: never

version:${base}:
  variables:
    PARENT_CI_PIPELINE_SOURCE: "${PARENT_CI_PIPELINE_SOURCE}"
    PARENT_CI_COMMIT_REF_NAME: "${PARENT_CI_COMMIT_REF_NAME}"
    PARENT_DEFAULT_BRANCH: "${PARENT_DEFAULT_BRANCH}"
    PARENT_CI_COMMIT_TAG: ${PARENT_CI_COMMIT_TAG}
    PARENT_COMMIT_BRANCH: "${PARENT_COMMIT_BRANCH}"
  stage: versioning
  image: ${CHILD_JOB_IMAGE}
  tags:
    - x86_64
  script: |
    cd ${CI_PROJECT_DIR}/charts/${base}
    EXTRACTED_VERSION=\$(awk '/^version/ {print \$2}' Chart.yaml)
    sed -ri "s/^version:\s?\$EXTRACTED_VERSION/version: \$VERSION/" Chart.yaml
  artifacts:
    paths:
      - ${CI_PROJECT_DIR}
  needs:
    - pipeline: "${PARENT_PIPELINE_ID}"
      job: prep  
  rules:
    - if: \$PARENT_CI_PIPELINE_SOURCE == "push" && \$PARENT_CI_COMMIT_REF_NAME == \$PARENT_DEFAULT_BRANCH
    - if: \$PARENT_CI_COMMIT_TAG

package:${base}:
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
    PARENT_CI_PIPELINE_SOURCE: "${PARENT_CI_PIPELINE_SOURCE}"
    PARENT_CI_COMMIT_REF_NAME: "${PARENT_CI_COMMIT_REF_NAME}"
    PARENT_DEFAULT_BRANCH: "${PARENT_DEFAULT_BRANCH}"
    PARENT_CI_COMMIT_TAG: ${PARENT_CI_COMMIT_TAG}
    PARENT_COMMIT_BRANCH: "${PARENT_COMMIT_BRANCH}"
  stage: package
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
     helm package .
  needs:
    - pipeline: "${PARENT_PIPELINE_ID}"
      job: prep
    - version:${base}
  rules:
    - if: \$PARENT_CI_COMMIT_BRANCH == \$PARENT_DEFAULT_BRANCH && \$PARENT_CI_PIPELINE_SOURCE == 'merge_request_event'
    - if: \$PARENT_CI_PIPELINE_SOURCE == "push" && \$PARENT_CI_COMMIT_REF_NAME == \$PARENT_DEFAULT_BRANCH
    - if: \$PARENT_CI_COMMIT_TAG


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
    PARENT_CI_PIPELINE_SOURCE: "${PARENT_CI_PIPELINE_SOURCE}"
    PARENT_CI_COMMIT_REF_NAME: "${PARENT_CI_COMMIT_REF_NAME}"
    PARENT_DEFAULT_BRANCH: "${PARENT_DEFAULT_BRANCH}"
    PARENT_CI_COMMIT_TAG: ${PARENT_CI_COMMIT_TAG}
    PARENT_COMMIT_BRANCH: "${PARENT_COMMIT_BRANCH}"
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
     chart_file=\$(ls -l ${CI_PROJECT_DIR}/charts/${base}/${base}*.tgz | head -n 1 | awk '{print \$NF}')
     echo "FILE IS \$chart_file"
     helm cm-push \$chart_file stgngc
  needs:
    - pipeline: "${PARENT_PIPELINE_ID}"
      job: prep
    - package:${base}
  rules:
    - if: \$PARENT_CI_PIPELINE_SOURCE == "push" && \$PARENT_CI_COMMIT_REF_NAME == \$PARENT_DEFAULT_BRANCH
    - if: \$PARENT_CI_COMMIT_TAG

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
    PARENT_CI_PIPELINE_SOURCE: "${PARENT_CI_PIPELINE_SOURCE}"
    PARENT_CI_COMMIT_REF_NAME: "${PARENT_CI_COMMIT_REF_NAME}"
    PARENT_DEFAULT_BRANCH: "${PARENT_DEFAULT_BRANCH}"
    PARENT_CI_COMMIT_TAG: ${PARENT_CI_COMMIT_TAG}
    PARENT_COMMIT_BRANCH: "${PARENT_COMMIT_BRANCH}"
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
     chart_file=\$(ls -l ${CI_PROJECT_DIR}/charts/${base}/${base}*.tgz | head -n 1 | awk '{print \$NF}')
     echo "FILE IS \$chart_file"
     helm cm-push \$chart_file ngc
  needs:
    - pipeline: "${PARENT_PIPELINE_ID}"
      job: prep
    - package:${base}
  rules:
    - if: \$PARENT_CI_COMMIT_TAG
EOF
done

cat >> ${CI_PROJECT_DIR}/finalize.yml <<-EOF
no_helm_work:
  variables:
    CHART_CHANGES: "${CHART_CHANGES}"
    PARENT_CI_PIPELINE_SOURCE: "${PARENT_CI_PIPELINE_SOURCE}"
  stage: lint
  image: ${CHILD_JOB_IMAGE}
  tags:
    - x86_64
  script: |
    echo "No Helm chart work to check"
  rules:
    - if: \$PARENT_CI_PIPELINE_SOURCE == "merge_request_event" && \$CHART_CHANGES == "0"
    - when: never
EOF

yq -M ea '. as $item ireduce({}; . *+ $item)' ${CI_PROJECT_DIR}/template.yml ${CI_PROJECT_DIR}/workflow.yml ${CI_PROJECT_DIR}/*_stage.yml ${CI_PROJECT_DIR}/*_pipeline.yml ${CI_PROJECT_DIR}/finalize.yml > ${CI_PROJECT_DIR}/pipeline.yml
cat "${CI_PROJECT_DIR}/pipeline.yml"
