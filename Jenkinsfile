pipeline {
  agent any

  options {
    timestamps()
    disableConcurrentBuilds()
    ansiColor('xterm')
    buildDiscarder(logRotator(numToKeepStr: '30', artifactNumToKeepStr: '30'))
    timeout(time: 30, unit: 'MINUTES')
  }

  parameters {
    choice(name: 'DEPLOY_ENV', choices: ['staging', 'prod'], description: 'Where to deploy (prod requires approval)')
  }

  environment {
    // Python / venv
    VENV = "${WORKSPACE}/venv"

    // App naming
    APP_NAME = "devsecops-project1"

    // Container registry (example: GHCR). Replace with ECR/ACR/DockerHub if needed.
    REGISTRY = "ghcr.io"
    IMAGE_REPO = "your-org-or-user/${APP_NAME}"  // <-- change this
    IMAGE = "${REGISTRY}/${IMAGE_REPO}"

    // Tagging strategy: git sha + build number for traceability
    GIT_SHA = ""
    IMAGE_TAG = ""
  }

  stages {

    stage('Checkout') {
      steps {
        checkout scm
        script {
          env.GIT_SHA = sh(script: "git rev-parse --short HEAD", returnStdout: true).trim()
          env.IMAGE_TAG = "${env.GIT_SHA}-${env.BUILD_NUMBER}"
          echo "Using image tag: ${env.IMAGE}:${env.IMAGE_TAG}"
        }
      }
    }

    stage('Setup Python Environment') {
      steps {
        sh '''
          python3 -m venv "$VENV"
          . "$VENV/bin/activate"
          pip install --upgrade pip wheel setuptools
        '''
      }
    }

    stage('Install Dependencies') {
      steps {
        sh '''
          . "$VENV/bin/activate"
          pip install -r app/requirements.txt
          pip install pytest bandit pip-audit
        '''
      }
    }

    stage('Quality + Security (Code/Deps)') {
      parallel {
        stage('Unit Tests') {
          steps {
            sh '''
              . "$VENV/bin/activate"
              pytest -q
            '''
          }
        }

        stage('Bandit SAST') {
          steps {
            sh '''
              . "$VENV/bin/activate"
              bandit -r app -ll
            '''
          }
        }

        stage('Dependency Audit') {
          steps {
            sh '''
              . "$VENV/bin/activate"
              pip-audit -r app/requirements.txt
            '''
          }
        }
      }
    }

    stage('Build Docker Image') {
      steps {
        sh '''
          docker build \
            -t "$IMAGE:$IMAGE_TAG" \
            -f docker/Dockerfile .
        '''
      }
    }

    stage('Image Security Scan (Trivy)') {
      steps {
        // Trivy must be available on the agent OR run it via container.
        // If you don't have trivy installed, you can run: docker run aquasec/trivy ...
        sh '''
          if command -v trivy >/dev/null 2>&1; then
            trivy image --exit-code 1 --severity HIGH,CRITICAL "$IMAGE:$IMAGE_TAG"
          else
            docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest \
              image --exit-code 1 --severity HIGH,CRITICAL "$IMAGE:$IMAGE_TAG"
          fi
        '''
      }
    }

    stage('Push Image to Registry') {
      when { branch 'main' }
      steps {
        // ---- REQUIRED Jenkins Credentials ----
        // 1) container-registry-creds (Username/Password) OR use a token as password
        withCredentials([usernamePassword(credentialsId: 'container-registry-creds',
                                          usernameVariable: 'REG_USER',
                                          passwordVariable: 'REG_PASS')]) {
          sh '''
            echo "$REG_PASS" | docker login "$REGISTRY" -u "$REG_USER" --password-stdin
            docker push "$IMAGE:$IMAGE_TAG"
            docker logout "$REGISTRY"
          '''
        }
      }
    }

    stage('Deploy to Staging') {
      when { allOf { branch 'main'; expression { params.DEPLOY_ENV == 'staging' || params.DEPLOY_ENV == 'prod' } } }
      steps {
        // ---- REQUIRED Jenkins Credentials ----
        // 2) kubeconfig-staging (Secret file) OR use a service account token method
        withCredentials([file(credentialsId: 'kubeconfig-staging', variable: 'KUBECONFIG_FILE')]) {
          sh '''
            export KUBECONFIG="$KUBECONFIG_FILE"
            kubectl -n staging set image deploy/"$APP_NAME" "$APP_NAME"="$IMAGE:$IMAGE_TAG" --record
            kubectl -n staging rollout status deploy/"$APP_NAME" --timeout=120s
          '''
        }
      }
    }

    stage('Smoke Test (Staging)') {
      when { allOf { branch 'main'; expression { params.DEPLOY_ENV == 'staging' || params.DEPLOY_ENV == 'prod' } } }
      steps {
        // Adjust URL for your staging endpoint (Ingress/ALB/etc.)
        sh '''
          STAGING_URL="https://staging.example.com/health"
          echo "Hitting $STAGING_URL"
          curl -fsS "$STAGING_URL" >/dev/null
        '''
      }
    }

    stage('Approval to Deploy PROD') {
      when { allOf { branch 'main'; expression { params.DEPLOY_ENV == 'prod' } } }
      steps {
        input message: "Deploy ${IMAGE}:${IMAGE_TAG} to PRODUCTION?", ok: "Yes, deploy"
      }
    }

    stage('Deploy to Production') {
      when { allOf { branch 'main'; expression { params.DEPLOY_ENV == 'prod' } } }
      steps {
        // ---- REQUIRED Jenkins Credentials ----
        // 3) kubeconfig-prod (Secret file)
        withCredentials([file(credentialsId: 'kubeconfig-prod', variable: 'KUBECONFIG_FILE')]) {
          sh '''
            export KUBECONFIG="$KUBECONFIG_FILE"
            kubectl -n prod set image deploy/"$APP_NAME" "$APP_NAME"="$IMAGE:$IMAGE_TAG" --record
            kubectl -n prod rollout status deploy/"$APP_NAME" --timeout=180s
          '''
        }
      }
    }
  }

  post {
    always {
      echo "Pipeline Completed: ${currentBuild.currentResult}"
      // Clean workspace and avoid leaving venv behind
      sh 'rm -rf "$VENV" || true'
      cleanWs(deleteDirs: true, notFailBuild: true)
    }
    success {
      echo "✔ SUCCESS: Build/Test/Scan/Deploy pipeline passed"
    }
    failure {
      echo "❌ FAILURE: Check logs above (tests/scans/build/deploy)"
    }
  }
}
