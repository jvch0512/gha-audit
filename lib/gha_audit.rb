# frozen_string_literal: true

require "yaml"
require "json"
require "cgi"

# Static audit of GitHub Actions workflows. Ruby standard library only.
module GhaAudit
  Finding = Struct.new(:file, :rule, :severity, :job, :step, :message, :fix, keyword_init: true)

  RULES = {
    "GHA001" => ["critical", "pull_request_target checks out untrusted pull request code", "Do not check out the PR head in a pull_request_target workflow, or split the workflow: build untrusted code under pull_request without secrets, and run privileged steps in a separate workflow_run job."],
    "GHA002" => ["high", "Untrusted input used in a run script (script injection)", "Pass the value through an environment variable and reference it as a shell variable, never inline ${{ }} inside run."],
    "GHA003" => ["medium", "Third-party action not pinned to a commit SHA", "Pin to the full 40-character commit SHA and keep the tag in a comment, so a moved tag cannot change what runs."],
    "GHA004" => ["medium", "Workflow has no explicit permissions or grants write-all", "Set permissions: contents: read at the top and grant more per job only where needed."],
    "GHA005" => ["high", "Remote script piped into a shell", "Download, verify a checksum or signature, then run."],
    "GHA006" => ["high", "Self-hosted runner reachable from pull requests", "Do not run untrusted code on self-hosted runners, or use ephemeral isolated runners and restrict who can trigger them."],
    "GHA007" => ["high", "Insecure commands re-enabled", "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and use environment files."],
    "GHA008" => ["medium", "Secrets passed to a reusable workflow with inherit", "Pass only the secrets the called workflow needs."]
  }.freeze

  UNTRUSTED = %w[
    github.event.issue.title github.event.issue.body github.event.pull_request.title github.event.pull_request.body
    github.event.pull_request.head.ref github.event.pull_request.head.label github.event.pull_request.head.repo.default_branch
    github.event.comment.body github.event.review.body github.event.review_comment.body github.event.head_commit.message
    github.event.head_commit.author.email github.event.head_commit.author.name github.head_ref github.event.workflow_run.head_branch
    github.event.workflow_run.head_commit.message github.event.pages.page_name github.event.commits
  ].freeze

  class Error < StandardError; end

  module_function

  def audit_text(file, text)
    doc = YAML.safe_load(text, aliases: false)
    raise Error, "#{file}: not a workflow (expected a mapping)" unless doc.is_a?(Hash)

    out = []
    triggers = events(doc)
    jobs = doc["jobs"].is_a?(Hash) ? doc["jobs"] : {}
    add = lambda do |rule, job, step, msg = nil|
      sev, title, fix = RULES.fetch(rule)
      out << Finding.new(file: file, rule: rule, severity: sev, job: job, step: step, message: msg || title, fix: fix)
    end

    if doc["permissions"].nil? && jobs.values.none? { |j| j.is_a?(Hash) && j["permissions"] }
      add.call("GHA004", nil, nil, "No permissions block: the token gets the repository default, often read-write")
    elsif doc["permissions"] == "write-all"
      add.call("GHA004", nil, nil, "permissions: write-all")
    end

    jobs.each do |jname, job|
      next unless job.is_a?(Hash)

      add.call("GHA004", jname, nil, "permissions: write-all") if job["permissions"] == "write-all"
      add.call("GHA008", jname, nil) if job["secrets"] == "inherit"
      ju = job["uses"].to_s
      add.call("GHA003", jname, ju, "reusable workflow #{ju} is not pinned to a commit SHA") if !ju.empty? && !ju.start_with?("./") && !ju.match?(/@[0-9a-f]{40}\z/)
      runs_on = Array(job["runs-on"]).flatten.map(&:to_s)
      if runs_on.include?("self-hosted") && (triggers & %w[pull_request pull_request_target issue_comment]).any?
        add.call("GHA006", jname, nil)
      end
      env_flags = [doc["env"], job["env"]].compact.select { |e| e.is_a?(Hash) }
      add.call("GHA007", jname, nil) if env_flags.any? { |e| e["ACTIONS_ALLOW_UNSECURE_COMMANDS"].to_s == "true" }
      Array(job["steps"]).each_with_index do |st, i|
        next unless st.is_a?(Hash)

        label = st["name"] || st["uses"] || "step #{i + 1}"
        uses = st["uses"].to_s
        if uses.start_with?("actions/checkout") && triggers.include?("pull_request_target")
          ref = st.dig("with", "ref").to_s
          add.call("GHA001", jname, label) if ref.match?(/pull_request\.head\.(sha|ref)|github\.head_ref|refs\/pull/)
        end
        if !uses.empty? && !uses.start_with?("./", "docker://") && !uses.match?(/@[0-9a-f]{40}\z/)
          owner = uses.split("/").first
          unless %w[actions github].include?(owner) && !uses.include?("@main") && !uses.include?("@master")
            add.call("GHA003", jname, label, "#{uses} is not pinned to a commit SHA")
          end
        end
        script = st["run"].to_s
        next if script.empty?

        script.scan(/\$\{\{\s*([^}]+?)\s*\}\}/).flatten.each do |expr|
          bare = expr.gsub(/\[.*?\]/, "")
          if UNTRUSTED.any? { |u| bare.start_with?(u) } || bare.match?(/github\.event\.(issue|pull_request|comment|review)\.[\w.]*(title|body|ref|label|message)\z/)
            add.call("GHA002", jname, label, "${{ #{expr} }} is attacker-controlled and expanded into a shell script")
          end
        end
        add.call("GHA005", jname, label) if script.match?(/(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b/)
      end
    end
    out
  rescue Psych::SyntaxError => e
    raise Error, "#{file}: invalid YAML (#{e.message.lines.first.strip})"
  end

  def events(doc)
    on = doc.key?("on") ? doc["on"] : doc[true]
    case on
    when String then [on]
    when Array then on.map(&:to_s)
    when Hash then on.keys.map(&:to_s)
    else []
    end
  end

  def audit_dir(dir)
    raise Error, "#{dir} is not a directory" unless File.directory?(dir)

    files = Dir.glob(File.join(dir, "**", "*.{yml,yaml}")).sort
    files.flat_map { |f| audit_text(f.delete_prefix("#{dir}/"), File.read(f)) }
  end

  SEV = { "critical" => 0, "high" => 1, "medium" => 2 }.freeze

  def sort(fs) = fs.sort_by { |f| [SEV[f.severity], f.file, f.job.to_s] }

  def text(fs)
    return "No findings.\n" if fs.empty?

    sort(fs).map { |f| "#{f.severity.upcase.ljust(8)} #{f.rule} #{f.file}#{f.job ? " > #{f.job}" : ""}#{f.step ? " > #{f.step}" : ""}\n         #{f.message}\n         Fix: #{f.fix}\n" }.join
  end

  def json(fs) = JSON.pretty_generate(sort(fs).map(&:to_h)) + "\n"

  def page(fs)
    h = ->(s) { CGI.escapeHTML(s.to_s) }
    rows = sort(fs).map { |f| "<tr><td class=\"#{f.severity}\">#{f.severity}</td><td>#{f.rule}</td><td>#{h[f.file]}#{f.job ? " &gt; #{h[f.job]}" : ""}</td><td>#{h[f.message]}<br><span class=\"sub\">Fix: #{h[f.fix]}</span></td></tr>" }.join
    <<~HTML
      <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>gha-audit</title><style>:root{color-scheme:dark}body{margin:0;padding:28px;background:#0e1319;color:#e8eef5;font:14px/1.5 system-ui,sans-serif}h1{margin:0 0 4px}.sub{color:#8b98a8}table{border-collapse:collapse;width:100%;margin-top:14px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2a3441;vertical-align:top}th{color:#8b98a8}td.critical{color:#f85149;font-weight:700}td.high{color:#f0883e;font-weight:700}td.medium{color:#e3b341;font-weight:700}</style></head><body><h1>gha-audit</h1><p class="sub">Static audit of GitHub Actions workflows. Ruby, standard library only. Report on the synthetic workflows in examples/.</p><p><b>#{fs.size}</b> findings.</p><table><tr><th>Severity</th><th>Rule</th><th>Where</th><th>What and how to fix</th></tr>#{rows}</table></body></html>
    HTML
  end
end
