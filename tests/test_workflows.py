import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RetentionWorkflowTests(unittest.TestCase):
  def workflow(self, name):
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")

  def test_live_plan_installs_rclone_and_uses_the_exact_workflow_revision(self):
    workflow = self.workflow("reusable-retention-plan.yml")

    self.assertIn("sudo apt-get install --yes rclone", workflow)
    self.assertIn("ref: ${{ job.workflow_sha }}", workflow)
    self.assertNotIn("ref: main", workflow)

  def test_apply_is_manual_caller_only_and_protected(self):
    workflow = self.workflow("reusable-retention-apply.yml")

    self.assertIn("workflow_call:", workflow)
    self.assertNotIn("schedule:", workflow)
    self.assertNotIn("workflow_dispatch:", workflow)
    self.assertIn("environment: release-retention-production", workflow)
    self.assertIn("sudo apt-get install --yes rclone", workflow)
    self.assertIn("ref: ${{ job.workflow_sha }}", workflow)
    self.assertNotIn("ref: main", workflow)


if __name__ == "__main__":
  unittest.main()
