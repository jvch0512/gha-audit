# frozen_string_literal: true

require "minitest/autorun"
require_relative "../lib/gha_audit"

class GhaAuditTest < Minitest::Test
  def audit(yaml) = GhaAudit.audit_text("w.yml", yaml)
  def rules(yaml) = audit(yaml).map(&:rule)

  HEAD = "permissions:\n  contents: read\n"

  def test_pull_request_target_with_pr_head_checkout_is_critical
    y = "on: pull_request_target\n#{HEAD}jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
    f = audit(y).find { |x| x.rule == "GHA001" }
    assert_equal "critical", f.severity
  end

  def test_checkout_default_ref_under_pull_request_target_is_fine
    y = "on: pull_request_target\n#{HEAD}jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
    refute_includes rules(y), "GHA001"
  end

  def test_script_injection_detected_and_env_indirection_is_safe
    bad = "on: issues\n#{HEAD}jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo '${{ github.event.issue.title }}'\n"
    good = "on: issues\n#{HEAD}jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          T: ${{ github.event.issue.title }}\n        run: echo \"$T\"\n"
    assert_includes rules(bad), "GHA002"
    refute_includes rules(good), "GHA002"
  end

  def test_safe_expressions_in_run_are_not_flagged
    y = "on: push\n#{HEAD}jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.sha }} ${{ runner.os }}\n"
    refute_includes rules(y), "GHA002"
  end

  def test_unpinned_third_party_action_but_not_sha_or_official
    base = "on: push\n#{HEAD}jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: %s\n"
    assert_includes rules(format(base, "foo/bar@v1")), "GHA003"
    refute_includes rules(format(base, "foo/bar@#{"a" * 40}")), "GHA003"
    refute_includes rules(format(base, "actions/checkout@v4")), "GHA003"
    refute_includes rules(format(base, "./local")), "GHA003"
  end

  def test_permissions_rules
    assert_includes rules("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ls\n"), "GHA004"
    assert_includes rules("on: push\npermissions: write-all\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ls\n"), "GHA004"
    refute_includes rules("on: push\n#{HEAD}jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ls\n"), "GHA004"
  end

  def test_curl_pipe_shell
    y = "on: push\n#{HEAD}jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -sSL https://x.example/i.sh | bash\n"
    assert_includes rules(y), "GHA005"
  end

  def test_self_hosted_only_matters_for_pull_requests
    pr = "on: pull_request\n#{HEAD}jobs:\n  a:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: ls\n"
    push = pr.sub("pull_request", "push")
    assert_includes rules(pr), "GHA006"
    refute_includes rules(push), "GHA006"
  end

  def test_unsecure_commands_and_secrets_inherit
    assert_includes rules("on: push\n#{HEAD}env:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: true\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ls\n"), "GHA007"
    assert_includes rules("on: push\n#{HEAD}jobs:\n  a:\n    uses: o/r/.github/workflows/x.yml@#{"b" * 40}\n    secrets: inherit\n"), "GHA008"
  end

  def test_reusable_workflow_must_be_pinned
    assert_includes rules("on: push\n#{HEAD}jobs:\n  a:\n    uses: o/r/.github/workflows/x.yml@main\n"), "GHA003"
  end

  def test_invalid_input_raises
    assert_raises(GhaAudit::Error) { audit("a: [") }
    assert_raises(GhaAudit::Error) { audit("- just\n- a list\n") }
    assert_raises(GhaAudit::Error) { GhaAudit.audit_dir("/nonexistent") }
  end

  def test_sample_directory_and_html_escaping
    fs = GhaAudit.audit_dir(File.join(__dir__, "..", "examples", "workflows"))
    assert_equal %w[GHA001], fs.select { |f| f.severity == "critical" }.map(&:rule)
    refute fs.any? { |f| f.file == "ci.yml" }
    evil = GhaAudit::Finding.new(file: "<img src=x>", rule: "GHA001", severity: "critical", job: nil, step: nil, message: "<b>m</b>", fix: "f")
    refute_includes GhaAudit.page([evil]), "<img src=x>"
  end
end
