// Pipeline steps shown in the pull request scan setup guide.

/** The shell step a pipeline runs: request a scan, wait for it, and fail the build if the gate fails. */
function script(argusUrl: string, repository: string, pullRequest: string): string {
  return `set -eu
scan=$(curl -sS --fail-with-body -X POST "${argusUrl}/api/v1/ci/pull-requests" \\
  -H "Authorization: Bearer $ARGUS_TOKEN" -H "Content-Type: application/json" \\
  -d "{\\"repository\\": \\"${repository}\\", \\"pullRequest\\": ${pullRequest}, \\"failOn\\": \\"high\\"}") || { echo "Argus did not accept the scan: $scan"; exit 1; }
id=$(echo "$scan" | jq -r .id)
echo "Argus: $(echo "$scan" | jq -r .argusUrl)"
for i in $(seq 1 90); do
  status=$(echo "$scan" | jq -r .status)
  if [ "$status" = succeeded ] || [ "$status" = failed ]; then break; fi
  sleep 10
  scan=$(curl -fsS "${argusUrl}/api/v1/ci/pull-requests/$id" -H "Authorization: Bearer $ARGUS_TOKEN")
done
echo "$scan" | jq -r '"Argus scan \\(.status): gate \\(.gate // "n/a"), \\(.result.counts // {} | add // 0) new issue(s)"'
[ "$(echo "$scan" | jq -r .status)" = succeeded ] || { echo "$(echo "$scan" | jq -r .error)"; exit 1; }
[ "$(echo "$scan" | jq -r .gate)" = passed ]`;
}

const indent = (text: string, spaces: number) =>
  text
    .split('\n')
    .map((l) => ' '.repeat(spaces) + l)
    .join('\n');

export function githubWorkflow(argusUrl: string): string {
  return `# .github/workflows/argus.yml
name: Argus security scan
on:
  # pull_request_target also runs for pull requests from forks. It is safe here because this
  # job never checks out or runs the pull request's code: Argus fetches the code itself.
  pull_request_target:
    types: [opened, synchronize, reopened]
jobs:
  argus:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - name: Scan the pull request with Argus
        env:
          ARGUS_TOKEN: \${{ secrets.ARGUS_TOKEN }}
        run: |
${indent(script(argusUrl, '${{ github.repository }}', '${{ github.event.pull_request.number }}'), 10)}`;
}

export function bitbucketPipeline(argusUrl: string): string {
  return `# bitbucket-pipelines.yml (add ARGUS_TOKEN as a secured repository or workspace variable)
pipelines:
  pull-requests:
    '**':
      - step:
          name: Argus security scan
          image: alpine:3.20
          clone:
            enabled: false
          script:
            - apk add --no-cache curl jq
            - |
${indent(script(argusUrl, '$BITBUCKET_REPO_FULL_NAME', '$BITBUCKET_PR_ID'), 14)}`;
}
