import os
from pathlib import Path
import subprocess
import tempfile
import unittest


WORKFLOWS = Path(__file__).resolve().parents[1] / '.github/workflows'


def step_script(filename, name):
    text = (WORKFLOWS / filename).read_text()
    step = text.split('      - name: ' + name + '\n', 1)[1].split('      - ', 1)[0]
    script = step.split('        run: |\n', 1)[1]
    return '\n'.join(line[10:] for line in script.splitlines())


class ReleaseTagTests(unittest.TestCase):
    def run_step(self, filename, name, env, root):
        output = root / 'output'
        output.write_text('')
        result = subprocess.run(
            ['bash', '-e', '-o', 'pipefail', '-c', step_script(filename, name)],
            env={**os.environ, **env, 'RUNNER_TEMP': str(root), 'GITHUB_OUTPUT': str(output)},
            capture_output=True, text=True, timeout=10,
        )
        return result, dict(line.split('=', 1) for line in output.read_text().splitlines())

    def test_actual_built_tag_is_used_by_both_publishers(self):
        for event, ref, tag in [
            ('push', 'refs/tags/v0.4.1', ''),
            ('workflow_dispatch', 'refs/heads/main', 'v0.4.1'),
            ('workflow_dispatch', 'refs/tags/v0.4.1', 'v0.4.1'),
        ]:
            with self.subTest(event=event, ref=ref), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                result, built = self.run_step('binary-build.yml', 'Determine release tag', {
                    'EVENT_NAME': event, 'GITHUB_REF': ref, 'INPUT_TAG': tag,
                }, root)
                self.assertEqual(result.returncode, 0, result.stderr)
                for filename, name in [
                    ('npm-publish-manual.yml', 'Normalize version'),
                    ('cargo-publish.yml', 'Resolve release tag'),
                ]:
                    result, published = self.run_step(filename, name, {'EVENT_NAME': 'workflow_run'}, root)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(published['tag'], built['tag'])
                    workflow = (WORKFLOWS / filename).read_text()
                    self.assertIn("github.event.workflow_run.conclusion == 'success'", workflow)
                    self.assertIn('run-id: ${{ github.event.workflow_run.id }}', workflow)
                    self.assertNotIn('head_branch', workflow)
                    output_id = 'version' if filename.startswith('npm') else 'tag'
                    self.assertIn('ref: ${{ steps.' + output_id + '.outputs.tag }}', workflow)

    def test_manual_publish_and_invalid_metadata(self):
        for filename, name in [
            ('npm-publish-manual.yml', 'Normalize version'),
            ('cargo-publish.yml', 'Resolve release tag'),
        ]:
            for value in ['0.4.1', 'v0.4.1', 'v0.5.0-rc.1', 'main', 'v1.2.3/evil', 'v1.2.3\nv9.9.9', '']:
                with self.subTest(file=filename, value=value), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    result, output = self.run_step(filename, name, {
                        'EVENT_NAME': 'workflow_dispatch', 'INPUT_REF': value,
                    }, root)
                    self.assertEqual(result.returncode == 0, value in ['0.4.1', 'v0.4.1', 'v0.5.0-rc.1'])
                    if result.returncode == 0:
                        self.assertEqual(output['tag'], 'v' + value.removeprefix('v'))
            with tempfile.TemporaryDirectory() as temp:
                result, _ = self.run_step(filename, name, {'EVENT_NAME': 'workflow_run'}, Path(temp))
                self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
