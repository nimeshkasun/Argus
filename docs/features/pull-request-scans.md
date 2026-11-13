# Pull request scans

A CI pipeline (GitHub Actions, Bitbucket Pipelines, Jenkins, …) can ask Argus to scan a pull request. Argus fetches the pull request itself, runs every enabled scanner, and comments on the pull request with the issues it **introduces**, each with how to fix it. The pipeline waits for the result and fails the build when a new issue reaches the chosen severity.

## How it works

1. The pipeline calls `POST /api/v1/ci/pull-requests` with an Argus API token, the repository name and the pull request number.
2. Argus reads the pull request through the **source's own credentials**: its commit, branches and changed files come from the provider, never from the request. The repository must be known to Argus and monitored.
3. A worker fetches the pull request's head (GitHub `refs/pull/<n>/head`, Bitbucket Data Center `refs/pull-requests/<n>/from`, Bitbucket Cloud the source branch, from the fork if there is one) into a temporary folder, and runs the scanners. The folder is deleted afterwards.
4. Argus keeps the issues the pull request **introduces**: findings in files it adds or changes that the repository did not already have. Issues already known in those files are counted but do not fail the gate, and suppressions (including `.argus.yml`) apply as usual.
5. Argus posts **one comment** on the pull request and updates it on every later scan, rather than adding new ones.
6. The pipeline polls `GET /api/v1/ci/pull-requests/<id>` until the scan has finished, and passes or fails on `gate`.

A pull request scan is a **preview**: its findings are not added to the repository, they open no tickets, and they do not change the dependency inventory. The repository's own scans (schedule, push, **Scan now**) remain the record. So that "new" means new, keep the repository's own scans running: the comparison is against its latest findings.

Pull request scans appear on the repository page under **Pull requests**, with their result and a link to the comment. They are kept as long as scan runs (90 days by default).

## The comment

- A headline with the gate result, the number of new issues, the commit and a link to the scan in Argus (when `ARGUS_PUBLIC_URL` is set).
- A table of new issues by severity.
- Each issue, most severe first: severity, title, a link to the file and line at the scanned commit, the rule, the risk score and a link to the advisory or rule, then **how to fix it**:
  - the scanner's remediation (for example the fixed version, or Trivy's resolution for a misconfiguration);
  - for a vulnerable **direct** dependency, the command that applies the fix: `npm install lodash@4.17.21`, `dotnet add package …`, `go get …`, `cargo update -p … --precise …`, and so on;
  - optionally an **AI-suggested code change** for code and infrastructure issues (below).
- Optionally an **AI code review** of the changes (below).
- Notes: issues already known in the changed files, issues covered by a suppression, and scanners that could not complete.

On GitHub the issues are collapsible sections (the five most severe start open). Bitbucket renders no HTML, so there each issue is a short section. The comment stays below 30,000 characters; further issues are linked to Argus.

Everything in the comment that comes from the repository (file names, code-derived titles) is escaped: a pull request cannot use it to add links, images or HTML, or to @mention people.

## AI fix suggestions (optional)

Turn on **Pull request fix suggestions** under **Administration → AI**. For the five most severe new code and infrastructure issues, Argus sends the issue and the lines around it (secrets redacted, within the AI context limit) to the configured AI provider and asks for the smallest change to the flagged lines. Suggestions with low confidence are dropped. In the comment they are marked as AI suggestions to review before applying. The usual AI controls apply: the repository's AI opt-out, the monthly budget, and the audit log.

## AI code review (optional)

Turn on **Pull request code review** under **Administration → AI**. Argus then also reviews the pull request's changes the way a careful engineer would: bugs and wrong logic, unhandled errors and edge cases, security problems, performance problems, and changed behaviour without a test. It does not comment on formatting or naming.

- **What is reviewed.** The diff of the pull request against the point where its branch left the base branch: the changed regions of each file with three lines of context. Lock files, minified or generated code, build output, binaries and deleted files are left out. Files are added in order until the AI **context limit** is reached; the comment says how many files were not reviewed. Raise the context limit for larger pull requests.
- **What is sent.** Those diff lines, the pull request title and the titles of the issues the scanners found (so the review does not repeat them). Secrets are redacted first, as in every AI request.
- **Where it shows.** An **AI code review** section in the same pull request comment: a short summary, then up to 10 remarks, each with a severity (*issue*, *suggestion*, *nitpick*), a category, and a link to the file and line. Remarks that point at a line the diff does not contain are dropped. The same review is shown on the scan in Argus and in the API result as `review`.
- **It is advisory.** The review never changes the gate, opens no tickets and stores no findings. It is labelled with the model that wrote it. If the AI provider fails, or the budget is used up, the scan still completes without a review.

### Inline comments

By default the remarks are listed in the summary comment. Turn on **Post remarks as inline comments** (under the feature's switch) to post each remark on its line of the pull request instead, like a reviewer's comment: on GitHub as a review comment, on Bitbucket Cloud and Data Center as an inline comment that can be replied to and resolved. The summary comment then keeps the overview and says how many remarks were posted inline.

- Each inline comment names its severity and category and is marked as an AI-assisted review posted by Argus.
- A new scan reviews the pull request afresh: it removes the inline comments the previous scan posted, then posts the new ones. A comment the provider refuses to delete (for example one with replies on Bitbucket Data Center) stays.
- A remark that cannot be posted inline (no permission, or the provider does not accept the line) is listed in the summary comment instead.
- It needs the same permission as the summary comment (see **Let Argus comment** below). Requests made with `"comment": false` post no inline comments either.

It needs one extra fetch of the base branch per scan and one AI request per scan. The usual AI controls apply: the repository's AI opt-out, the monthly budget, and the audit log (`ai.request`, use case `pr_review`).

## Setting it up

### 1. Let Argus comment

The source's credentials need to be allowed to comment on pull requests (scanning alone needs only read access):

| Source | Permission to add |
|---|---|
| GitHub, fine-grained token | **Pull requests: Read and write** |
| GitHub, classic token | `repo` (already required) |
| GitHub App | Repository permission **Pull requests: Read and write** (accept the updated permissions on the installation) |
| Bitbucket Cloud access token / API token | **Pull requests: Write** (`pullrequest:write`) |
| Bitbucket Data Center | **Repository read** is enough to comment |

Without it, the scan still runs and the pipeline still gets the result; the scan records why the comment could not be posted.

### 2. Create a token for the pipeline

Under **Profile → API tokens**, create a token with the **CI pull request scans** preset (`scans:run` and `repos:read`). The token's owner must be able to see the repository (their role, or their team for Developers). Store it in the pipeline as a secret named `ARGUS_TOKEN`.

### 3. Add the pipeline step

The repository page's **Pull requests → Set up CI** shows both snippets below with your Argus address filled in.

**GitHub Actions** (`.github/workflows/argus.yml`):

```yaml
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
          ARGUS_TOKEN: ${{ secrets.ARGUS_TOKEN }}
        run: |
          set -eu
          scan=$(curl -sS --fail-with-body -X POST "https://argus.example.com/api/v1/ci/pull-requests" \
            -H "Authorization: Bearer $ARGUS_TOKEN" -H "Content-Type: application/json" \
            -d "{\"repository\": \"${{ github.repository }}\", \"pullRequest\": ${{ github.event.pull_request.number }}, \"failOn\": \"high\"}") || { echo "Argus did not accept the scan: $scan"; exit 1; }
          id=$(echo "$scan" | jq -r .id)
          echo "Argus: $(echo "$scan" | jq -r .argusUrl)"
          for i in $(seq 1 90); do
            status=$(echo "$scan" | jq -r .status)
            if [ "$status" = succeeded ] || [ "$status" = failed ]; then break; fi
            sleep 10
            scan=$(curl -fsS "https://argus.example.com/api/v1/ci/pull-requests/$id" -H "Authorization: Bearer $ARGUS_TOKEN")
          done
          echo "$scan" | jq -r '"Argus scan \(.status): gate \(.gate // "n/a"), \(.result.counts // {} | add // 0) new issue(s)"'
          [ "$(echo "$scan" | jq -r .status)" = succeeded ] || { echo "$(echo "$scan" | jq -r .error)"; exit 1; }
          [ "$(echo "$scan" | jq -r .gate)" = passed ]
```

**Bitbucket Pipelines** (`bitbucket-pipelines.yml`, with `ARGUS_TOKEN` as a secured repository or workspace variable): the same script in a `pull-requests` pipeline, using `$BITBUCKET_REPO_FULL_NAME` and `$BITBUCKET_PR_ID`, in an `alpine` step with `apk add --no-cache curl jq` and `clone: enabled: false` (the step needs no checkout).

**Other CI systems** (Jenkins or Bamboo with Bitbucket Data Center, …): call the same API with the repository as Argus names it (`PROJECT/repo`) and the pull request number.

To make the check required, add it to the branch protection rules (GitHub) or merge checks (Bitbucket).

## API

### `POST /api/v1/ci/pull-requests`

Needs the `scans:run` permission.

| Field | Required | Description |
|---|---|---|
| `repository` | yes | The repository as Argus names it: `owner/repo` (GitHub), `workspace/repo` (Bitbucket Cloud) or `PROJECT/repo` (Bitbucket Data Center). Case does not matter. |
| `pullRequest` | yes | The pull request number. |
| `failOn` | no | `critical`, `high` (default), `medium`, `low` or `never` (report only). |
| `comment` | no | `false` skips the pull request comment. Default `true`. |
| `sourceId` | no | Chooses the source when two sources contain a repository with the same name. |

Responses:
- `202` with the queued scan.
- `200` with the existing scan when the same commit of the pull request is already queued or running.
- `404` when the repository is unknown to Argus or not visible to the token's owner, or the pull request does not exist.
- `409` when the repository is not monitored, or the pull request is merged, closed or declined.

### `GET /api/v1/ci/pull-requests/<id>`

Needs `repos:read`. Returns the scan:
- `status`: `queued`, `running`, `succeeded` or `failed`;
- `gate`: `passed` or `failed`, once succeeded;
- `result`: changed files, new-issue counts by severity, the new issues with their fixes, known and suppressed counts, per-scanner status, and `review` (the AI code review, when that feature is on);
- `commentUrl`, `error`, and `argusUrl`.

`GET /api/v1/ci/pull-requests?repoId=<id>` lists a repository's pull request scans, newest first.

Requests are audited as `pr_scan.requested`.
