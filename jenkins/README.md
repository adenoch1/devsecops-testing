## CI/CD (Jenkins) — Jenkinsfile.lite

This repo includes a **learning-friendly Jenkins pipeline** located at:

- `jenkins/Jenkinsfile.lite`

It is intentionally **small and readable**, but follows **production habits** (tests, security checks, traceable image tags).

### What Jenkinsfile.lite does
On each run, the pipeline:

1. **Checks out** the code from Git
2. Creates a **Python virtual environment**
3. Installs dependencies from `app/requirements.txt`
4. Runs **unit tests** with `pytest`
5. Runs basic **security checks**
   - `bandit` (SAST for Python)
   - `pip-audit` (dependency vulnerability audit)
6. Builds a **Docker image** using `docker/Dockerfile` and tags it as:
   - `devsecops-project1:latest`
   - `devsecops-project1:<git-sha>` (short SHA for traceability)

> Note: This pipeline currently builds the image locally on the Jenkins agent’s Docker engine.
> If Jenkins is running in a container, it must have access to the host Docker engine (commonly via mounting `/var/run/docker.sock`)
> for the image to appear in Docker Desktop.

---

### How to configure Jenkins to use Jenkinsfile.lite
In Jenkins (Pipeline job):

- Definition: **Pipeline script from SCM**
- SCM: Git
- Repository URL: *(your repo URL)*
- Branch: `main` (or your preferred branch)
- Script Path:
