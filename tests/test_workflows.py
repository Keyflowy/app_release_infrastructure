import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RetentionWorkflowTests(unittest.TestCase):
  def workflow(self, name):
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")

  def assert_runner_local_contract(self, workflow):
    self.assertIn("runs-on: ${{ fromJSON(inputs.runs_on) }}", workflow)
    self.assertIn(r'default: "[\"self-hosted\",\"Linux\",\"home\"]"', workflow)
    self.assertIn("RUNNER_ENVIRONMENT", workflow)
    self.assertIn("RUNNER_OS", workflow)
    self.assertIn("command -v rclone", workflow)
    self.assertIn("rclone listremotes", workflow)
    self.assertIn("cf_r2:", workflow)
    self.assertIn("gd_admin:", workflow)
    self.assertIn("rclone lsd", workflow)
    self.assertNotIn("RCLONE_CONFIG", workflow)
    self.assertNotIn("sudo apt-get install --yes rclone", workflow)

  def test_live_plan_uses_runner_local_rclone_and_the_exact_workflow_revision(self):
    workflow = self.workflow("reusable-retention-plan.yml")

    self.assert_runner_local_contract(workflow)
    self.assertIn("ref: ${{ job.workflow_sha }}", workflow)
    self.assertNotIn("ref: main", workflow)

  def test_apply_is_manual_caller_only_protected_and_uses_runner_local_rclone(self):
    workflow = self.workflow("reusable-retention-apply.yml")

    self.assertIn("workflow_call:", workflow)
    self.assertNotIn("schedule:", workflow)
    self.assertNotIn("workflow_dispatch:", workflow)
    self.assertIn("environment: release-retention-production", workflow)
    self.assert_runner_local_contract(workflow)
    self.assertIn("ref: ${{ job.workflow_sha }}", workflow)
    self.assertNotIn("ref: main", workflow)


if __name__ == "__main__":
  unittest.main()
