#!/bin/bash

set -eux pipefail
CHART_ROOTDIR=${CI_PROJECT_DIR}/charts


FORMATTED_CHANGES=($(awk '/charts/' ${CI_PROJECT_DIR}/CHANGES.txt | cut -d '/' -f1-2 | uniq)) 
# To prevent the job trigger:generate_pipelines from failing, we set CHART_CHANGES based on
# actual helm code changes.  If there are no actual changes then we will create a bogus job which
# always succeeds
if [[ "${#FORMATTED_CHANGES[@]}" -ne 0 ]]; then
  CHART_CHANGES="1"
  CHARTS=($(find charts/ -mindepth 1 -maxdepth 1 -type d))
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
  - deploy
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
    yamllint  --config-file ${CI_PROJECT_DIR}/.gitlab/ci/yamllint.yaml values.yaml
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

test:${base}_KubeLint:
  variables:
    HELM_CACHE_HOME: "${HELM_CACHE_HOME}"
    HELM_CONFIG_HOME: "${HELM_CONFIG_HOME}"
    HELM_DATA_HOME: "${HELM_DATA_HOME}"
    HELM_REGISTRY_CONFIG: "${HELM_REGISTRY_CONFIG}"
    HELM_REPOSITORY_CACHE: "${HELM_REPOSITORY_CACHE}"
    HELM_REPOSITORY_CONFIG: "${HELM_REPOSITORY_CONFIG}"
    HELM_PLUGINS: "${HELM_PLUGINS}"
    PARENT_CI_PIPELINE_SOURCE: "${PARENT_CI_PIPELINE_SOURCE}"
  stage: test
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
    kube-linter --with-color lint .
  needs:
    - pipeline: "${PARENT_PIPELINE_ID}"
      job: prep
    - lint:${base}
  rules:
    - if: \$PARENT_CI_PIPELINE_SOURCE == "merge_request_event"
      changes:
        - "charts/**/*"
    - when: never
  allow_failure: true

version:${base}:
  variables:
    PARENT_CI_PIPELINE_SOURCE: "${PARENT_CI_PIPELINE_SOURCE}"
    PARENT_CI_COMMIT_REF_NAME: "${PARENT_CI_COMMIT_REF_NAME}"
    PARENT_DEFAULT_BRANCH: "${PARENT_DEFAULT_BRANCH}"
    PARENT_CI_COMMIT_TAG: ${PARENT_CI_COMMIT_TAG}
    PARENT_COMMIT_BRANCH: "${PARENT_COMMIT_BRANCH}"
    PARENT_PIPELINE_ID: "${PARENT_PIPELINE_ID}"
  stage: versioning
  image: ${CHILD_JOB_IMAGE}
  tags:
    - x86_64
  script: |
    echo "-------------- ${PARENT_PIPELINE_ID}"
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
  artifacts:
    paths:
      - ${CI_PROJECT_DIR}
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

cat >> ${CI_PROJECT_DIR}/deployment.yml <<-EOF
.deploy:
  stage: deploy
  variables:
    PARENT_PIPELINE_ID: "${PARENT_PIPELINE_ID}"
    PARENT_CI_JOB_TOKEN: "${PARENT_CI_JOB_TOKEN}"
    DEPLOYMNET_GIT_KEY: ${DEPLOYMENT_GIT_KEY}
    HELM_CACHE_HOME: "${HELM_CACHE_HOME}"
    HELM_CONFIG_HOME: "${HELM_CONFIG_HOME}"
    HELM_DATA_HOME: "${HELM_DATA_HOME}"
    HELM_REGISTRY_CONFIG: "${HELM_REGISTRY_CONFIG}"
    HELM_REPOSITORY_CACHE: "${HELM_REPOSITORY_CACHE}"
    HELM_REPOSITORY_CONFIG: "${HELM_REPOSITORY_CONFIG}"
    HELM_PLUGINS: "${HELM_PLUGINS}"
    CI_ENVIRONMENT_NAME: "${CI_ENVIRONMENT_NAME}"
  image: ${CHILD_JOB_IMAGE}
  script:
    - echo "Deploying to $CI_ENVIRONMENT_NAME"
    - git config user.name "carbide"
    - git config user.email "project77059_bot1@noreply.gitlab-master.nvidia.com"
    - cd \${CI_PROJECT_DIR}
    - git clone https://carbide:"${DEPLOYMENT_GIT_KEY}"@$CI_SERVER_HOST/nvmetal/forge-deployment.git --single-branch
    - cd \${CI_PROJECT_DIR}/forge-deployment
    - kubectl --kubeconfig ${CI_PROJECT_DIR}/.kubeconfig get pods -n forge-system
    - helm --kubeconfig ${CI_PROJECT_DIR}/.kubeconfig list -A
    - helm --kubeconfig ${CI_PROJECT_DIR}/.kubeconfig upgrade -i -n \${NAMESPACE} carbide --values ${CI_PROJECT_DIR}/forge-deployment/environments/$CI_ENVIRONMENT_NAME/fleetcommand/forge.yaml \
    --set carbideApi.container.image.tag=\$VERSION \
    --set carbidePxe.container.iamge.tag=\$VERSION \
    --set carbideDhcp.container.image.tag=\$VERSION \
    --set carbideDns.container.image.tag=\$VERSION \
    --debug \
    --dry-run .
  when: manual
  tags:
    - x86_64
  needs:
    - pipeline: "${PARENT_PIPELINE_ID}"
      job: prep
  rules:
    - if: \$PARENT_CI_PIPELINE_SOURCE == 'push' && PARENT_CI_COMMIT_REF_NAME == \$PARENT_DEFAULT_BRANCH
    - if: \$CI_COMMIT_TAG


deploy_dev2:
  extends: .deploy
  variables:
    NAMESPACE: forge-system
  environment:
    name: dev2
    deployment_tier: development
EOF

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
